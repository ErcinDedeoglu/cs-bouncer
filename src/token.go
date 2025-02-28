package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

const BouncerName = "cs-bouncer"

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

	// Generate new bouncer
	cmd := exec.Command("docker", "exec", crowdsecContainer, "cscli", "bouncers", "add", BouncerName, "-o", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker exec failed: %w | OUTPUT: %s", err, strings.TrimSpace(string(out)))
	}

	// Crowdsec returns a plain JSON string (not object), e.g. "TOKEN"
	var token string
	if err := json.Unmarshal(out, &token); err != nil {
		return "", fmt.Errorf("JSON string unmarshal failed: %w | RAW OUTPUT: %s", err, strings.TrimSpace(string(out)))
	}

	if token == "" {
		return "", fmt.Errorf("empty API key received. RAW OUTPUT: %s", strings.TrimSpace(string(out)))
	}

	log.Printf("Created new bouncer '%s' with api key.\n", BouncerName)
	return token, nil
}

// Check if bouncer already exists
func CheckBouncerExists(bouncerName, crowdsecContainer string) (bool, error) {
	cmd := exec.Command("docker", "exec", crowdsecContainer, "cscli", "bouncers", "inspect", bouncerName)
	err := cmd.Run()
	if err != nil {
		return false, nil // doesn't exist
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
