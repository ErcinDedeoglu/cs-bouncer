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

	// Optionally setup host dependencies (iptables-persistent) clearly based on ENV
	setupDependencies := strings.ToLower(os.Getenv("SETUP_HOST_DEPENDENCIES")) == "true"
	if setupDependencies {
		log.Println("[INIT] Installing host dependencies as per configuration.")
		if err := setupHostDependencies(); err != nil {
			log.Fatalf("[ERROR] Host dependencies initialization failed: %v", err)
		}
	} else {
		log.Println("[INIT] Host dependencies setup skipped (SETUP_HOST_DEPENDENCIES=false).")
	}

	if crowdsecURL == "" || syncIntervalStr == "" {
		log.Fatal("[ERROR] Missing environment variables: CROWDSEC_URL and SYNC_INTERVAL_SEC must be set.")
	}

	// Auto-generate CrowdSec API key if not provided explicitly
	if apiKey == "" {
		if autoGenerateKey == "true" {
			if crowdsecContainer == "" {
				log.Fatal("[ERROR] Missing CROWDSEC_CONTAINER_NAME environment variable when AUTO_GENERATE_API_KEY=true.")
			}
			log.Printf("[INIT] API key not supplied, auto-generating via CrowdSec (bouncer name: '%s').", BouncerName)
			var err error
			apiKey, err = CreateBouncerToken(crowdsecContainer)
			if err != nil {
				log.Fatalf("[ERROR] Generating token failed: %v", err)
			}
		} else {
			log.Fatal("[ERROR] CROWDSEC_API_KEY not set and AUTO_GENERATE_API_KEY is false.")
		}
	}

	syncIntervalSec, err := strconv.Atoi(syncIntervalStr)
	if err != nil || syncIntervalSec <= 0 {
		log.Fatal("[ERROR] SYNC_INTERVAL_SEC must be a positive integer.")
	}

	log.Println("[INIT] CrowdSec cs-bouncer started successfully.")
	log.Printf("[CONFIG] Sync interval set to: %d seconds", syncIntervalSec)
	log.Printf("[CONFIG] CrowdSec API configured at: %s", crowdsecURL)

	// Initialize IP ban state clearly (restore from iptables)
	currentBannedIPs, err := getCurrentlyBannedIPsFromIptables()
	if err != nil {
		log.Printf("[ERROR] Could not restore banned IPs from iptables: %v. Starting fresh.", err)
		currentBannedIPs = make(map[string]bool)
	} else {
		log.Printf("[INIT] Successfully restored %d banned IP(s) from iptables.", len(currentBannedIPs))
	}

	ticker := time.NewTicker(time.Duration(syncIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		log.Println("[SYNC] Fetching CrowdSec decisions now...")
		decisions, err := getCrowdsecDecisions(crowdsecURL, apiKey)
		if err != nil {
			log.Printf("[ERROR] Encountered error fetching decisions from CrowdSec: %v", err)
		} else {
			// Process CrowdSec banned IPs
			crowdsecIPCount := 0
			newBannedIPs := make(map[string]bool)
			for _, d := range decisions {
				if d.Type == "ban" && d.Scope == "Ip" {
					newBannedIPs[d.Value] = true
					crowdsecIPCount++
				}
			}

			// Retrieve current iptables IP count for statistics log clearly
			iptablesIPCount, err := countIptablesBannedIPs()
			if err != nil {
				log.Printf("[ERROR] Counting iptables IPs failed: %v", err)
			} else {
				log.Printf("[STATS] Total CrowdSec bans fetched: %d | Total iptables banned IPs: %d", crowdsecIPCount, iptablesIPCount)
			}

			var (
				banCount, unbanCount int
			)

			// Apply new CrowdSec IP bans clearly
			for ip := range newBannedIPs {
				if !currentBannedIPs[ip] {
					log.Printf("[BAN] New IP detected for banning: %s", ip)
					if err := banIP(ip); err != nil {
						log.Printf("[ERROR] Could NOT ban IP %s: %v", ip, err)
					} else {
						banCount++
					}
				}
			}

			// Remove IPs that no longer appear in CrowdSec decisions
			for ip := range currentBannedIPs {
				if !newBannedIPs[ip] {
					log.Printf("[UNBAN] Removing outdated IP ban: %s", ip)
					if err := unbanIP(ip); err != nil {
						log.Printf("[ERROR] Could NOT unban IP %s: %v", ip, err)
					} else {
						unbanCount++
					}
				}
			}

			if banCount == 0 && unbanCount == 0 {
				log.Println("[SYNC] IP ban/unban actions not required (no changes).")
			} else {
				log.Printf("[SYNC] Completed IP management cycle: %d banned newly | %d unbanned.", banCount, unbanCount)
			}

			// Update local currentBannedIPs map clearly for next iteration
			currentBannedIPs = newBannedIPs
		}

		// Optionally persist iptables rules permanently on the host
		persistIptablesRules()

		log.Printf("[WAIT] Idle now, waiting next sync trigger (%d seconds)...", syncIntervalSec)
		<-ticker.C
	}
}
