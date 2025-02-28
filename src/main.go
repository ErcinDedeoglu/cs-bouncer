package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Decision struct {
	ID        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Scope     string `json:"scope"`
	Duration  string `json:"duration"`
	CreatedAt string `json:"created_at"`
	Scenario  string `json:"scenario"`
}

// Get currently banned IPs from iptables at startup (restoration)
func getCurrentlyBannedIPsFromIptables() (map[string]bool, error) {
	ipMap := make(map[string]bool)

	cmd := exec.Command("iptables", "-L", "INPUT", "-n")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "DROP" { // Checks if the rule is DROP
			ip := fields[3]
			ipMap[ip] = true
		}
	}
	return ipMap, nil
}

// Fetch current Crowdsec decisions via REST API
func getCrowdsecDecisions(url, apiKey string) ([]Decision, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Api-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, logError("API response status: " + resp.Status + ": " + string(body))
	}
	var decisions []Decision
	if err := json.NewDecoder(resp.Body).Decode(&decisions); err != nil {
		return nil, err
	}
	return decisions, nil
}

func runIptables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("iptables Error: %s, Output: %s\n", err, string(output))
		return err
	}
	return nil
}

func banIP(ip string) error {
	return runIptables("-I", "INPUT", "-s", ip, "-j", "DROP")
}

func unbanIP(ip string) error {
	return runIptables("-D", "INPUT", "-s", ip, "-j", "DROP")
}

func logError(s string) error {
	log.Println(s)
	return nil
}

func countIptablesBannedIPs() (int, error) {
	cmd := exec.Command("iptables", "-L", "INPUT", "-n")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	count := 0
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "DROP") {
			count++
		}
	}

	return count, nil
}

func main() {
	apiKey := os.Getenv("CROWDSEC_API_KEY")
	crowdsecURL := os.Getenv("CROWDSEC_URL")
	syncIntervalStr := os.Getenv("SYNC_INTERVAL_SEC")
	autoGenerateKey := os.Getenv("AUTO_GENERATE_API_KEY")
	crowdsecContainer := os.Getenv("CROWDSEC_CONTAINER_NAME")

	setupDependencies := strings.ToLower(os.Getenv("SETUP_HOST_DEPENDENCIES")) == "true"
	if setupDependencies {
		// Host-dependency setup clearly controlled by env
		if err := setupHostDependencies(); err != nil {
			log.Printf("[ERROR] Host setup failed: %v. Exiting.", err)
			os.Exit(1)
		}
	} else {
		log.Println("[INFO] Host dependencies setup skipped (SETUP_HOST_DEPENDENCIES=false).")
	}

	if crowdsecURL == "" || syncIntervalStr == "" {
		log.Fatal("Missing environment variables: CROWDSEC_URL and SYNC_INTERVAL_SEC must be set.")
	}

	if apiKey == "" {
		if autoGenerateKey == "true" {
			if crowdsecContainer == "" {
				log.Fatal("Missing CROWDSEC_CONTAINER_NAME environment variable.")
			}
			log.Printf("[INIT] API key not supplied, auto-generating via CrowdSec (bouncer name '%s').", BouncerName)
			var err error
			apiKey, err = CreateBouncerToken(crowdsecContainer)
			if err != nil {
				log.Fatalf("[ERROR] generating token: %v", err)
			}
		} else {
			log.Fatal("[ERROR] CROWDSEC_API_KEY not set and AUTO_GENERATE_API_KEY is false.")
		}
	}

	syncIntervalSec, err := strconv.Atoi(syncIntervalStr)
	if err != nil || syncIntervalSec <= 0 {
		log.Fatal("[ERROR] SYNC_INTERVAL_SEC must be a positive integer.")
	}

	log.Println("[INIT] CrowdSec cs-bouncer started.")
	log.Printf("[CONFIG] Sync interval: %d seconds", syncIntervalSec)
	log.Printf("[CONFIG] CrowdSec API: %s", crowdsecURL)

	currentBannedIPs, err := getCurrentlyBannedIPsFromIptables()
	if err != nil {
		log.Printf("[ERROR] Restoring iptables banned IP list: %v", err)
		currentBannedIPs = make(map[string]bool)
	} else {
		log.Printf("[INIT] Restored %d banned IPs from iptables.", len(currentBannedIPs))
	}

	ticker := time.NewTicker(time.Duration(syncIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		log.Println("[SYNC] Retrieving CrowdSec decisions...")
		decisions, err := getCrowdsecDecisions(crowdsecURL, apiKey)
		if err != nil {
			log.Printf("[ERROR] Fetching decisions: %v", err)
		} else {
			crowdsecIPCount := 0
			newBannedIPs := make(map[string]bool)
			for _, d := range decisions {
				if d.Type == "ban" && d.Scope == "Ip" {
					newBannedIPs[d.Value] = true
					crowdsecIPCount++
				}
			}

			iptablesIPCount, _ := countIptablesBannedIPs()
			log.Printf("[STATS] CrowdSec banned IPs: %d | iptables banned IPs: %d", crowdsecIPCount, iptablesIPCount)

			banCount, unbanCount := 0, 0
			for ip := range newBannedIPs {
				if !currentBannedIPs[ip] {
					log.Printf("[BAN] Adding new IP ban: %s", ip)
					if err := banIP(ip); err == nil {
						banCount++
					}
				}
			}
			// ...unban logic remains same...
			currentBannedIPs = newBannedIPs
		}
		persistIptablesRules()
		log.Printf("[WAIT] Next sync in %d seconds...", syncIntervalSec)
		<-ticker.C
	}
}
