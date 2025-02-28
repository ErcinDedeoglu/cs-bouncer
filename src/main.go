package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
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

func main() {
	apiKey := os.Getenv("CROWDSEC_API_KEY")
	crowdsecURL := os.Getenv("CROWDSEC_URL")
	syncIntervalStr := os.Getenv("SYNC_INTERVAL_SEC")
	autoGenerateKey := os.Getenv("AUTO_GENERATE_API_KEY")
	bouncerName := os.Getenv("CROWDSEC_BOUNCER_NAME")
	crowdsecContainer := os.Getenv("CROWDSEC_CONTAINER_NAME")

	if crowdsecURL == "" || syncIntervalStr == "" {
		log.Fatal("Missing environment variables: CROWDSEC_URL and SYNC_INTERVAL_SEC must be set.")
	}

	if apiKey == "" {
		if autoGenerateKey == "true" {
			if bouncerName == "" || crowdsecContainer == "" {
				log.Fatal("AUTO_GENERATE_API_KEY is true, but missing CROWDSEC_BOUNCER_NAME or CROWDSEC_CONTAINER_NAME.")
			}
			log.Println("API key not supplied, auto-generating via CrowdSec.")
			var err error
			apiKey, err = CreateBouncerToken(bouncerName, crowdsecContainer)
			if err != nil {
				log.Fatalf("Error auto-generating token: %v\n", err)
			}
		} else {
			log.Fatal("CROWDSEC_API_KEY not set and AUTO_GENERATE_API_KEY is false. Set one to continue.")
		}
	}

	syncIntervalSec, err := strconv.Atoi(syncIntervalStr)
	if err != nil || syncIntervalSec <= 0 {
		log.Fatal("SYNC_INTERVAL_SEC must be a positive integer.")
	}

	log.Println("CrowdSec cs-bouncer started.")
	log.Printf("Syncing every %d seconds from %s\n", syncIntervalSec, crowdsecURL)

	currentBannedIPs := make(map[string]bool)

	for {
		decisions, err := getCrowdsecDecisions(crowdsecURL, apiKey)
		if err != nil {
			log.Printf("Error fetching decisions: %v\n", err)
		} else {
			newBannedIPs := make(map[string]bool)
			for _, d := range decisions {
				if d.Type == "ban" && d.Scope == "Ip" {
					newBannedIPs[d.Value] = true
					if !currentBannedIPs[d.Value] {
						log.Printf("Banning new IP: %s\n", d.Value)
						if err := banIP(d.Value); err != nil {
							log.Printf("Error banning IP %s: %v\n", d.Value, err)
						}
					}
				}
			}
			for ip := range currentBannedIPs {
				if !newBannedIPs[ip] {
					log.Printf("Unbanning removed IP: %s\n", ip)
					if err := unbanIP(ip); err != nil {
						log.Printf("Error unbanning IP %s: %v\n", ip, err)
					}
				}
			}
			currentBannedIPs = newBannedIPs
		}
		time.Sleep(time.Duration(syncIntervalSec) * time.Second)
	}
}
