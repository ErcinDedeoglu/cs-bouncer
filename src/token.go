package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

const BouncerName = "cs-bouncer"

type BouncerResponse struct {
	ApiKey string `json:"api_key"`
}

// CreateBouncerToken creates a new token (removes existing one automatically if present)
func CreateBouncerToken(crowdsecContainer string) (string, error) {
	exists, err := CheckBouncerExists(BouncerName, crowdsecContainer)
	if err != nil {
		return "", err
	}
	if exists {
		log.Printf("Bouncer '%s' already exists. Deleting...\n", BouncerName)
		if err := DeleteBouncer(BouncerName, crowdsecContainer); err != nil {
			return "", err
		}
		log.Printf("Old bouncer '%s' deleted.\n", BouncerName)
	}

	cmd := exec.Command("docker", "exec", crowdsecContainer, "cscli", "bouncers", "add", BouncerName, "-o", "json")
	out, err := cmd.CombinedOutput() // Using CombinedOutput to capture stderr too
	if err != nil {
		return "", fmt.Errorf("docker exec failed: %w | OUTPUT: %s", err, strings.TrimSpace(string(out)))
	}

	var resp BouncerResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", fmt.Errorf("JSON unmarshal failed: %w | RAW OUTPUT: %s", err, strings.TrimSpace(string(out)))
	}

	if resp.ApiKey == "" {
		return "", fmt.Errorf("empty API key received. RAW OUTPUT: %s", strings.TrimSpace(string(out)))
	}

	log.Printf("created new bouncer '%s' with api key.\n", BouncerName)
	return resp.ApiKey, nil
}

// Check if bouncer already exists
func CheckBouncerExists(bouncerName, crowdsecContainer string) (bool, error) {
	cmd := exec.Command("docker", "exec", crowdsecContainer, "cscli", "bouncers", "inspect", bouncerName)
	err := cmd.Run()
	if err != nil {
		return false, nil // implies not exists
	}
	return true, nil
}

// Delete existing bouncer
func DeleteBouncer(bouncerName, crowdsecContainer string) error {
	cmd := exec.Command("docker", "exec", crowdsecContainer, "cscli", "bouncers", "delete", bouncerName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting bouncer: %w, output: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
