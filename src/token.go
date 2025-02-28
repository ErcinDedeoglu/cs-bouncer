package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
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

	// Create new bouncer
	cmd := exec.Command("docker", "exec", crowdsecContainer, "cscli", "bouncers", "add", BouncerName, "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker exec error: %w, output: %s", err, string(out))
	}

	var resp BouncerResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", fmt.Errorf("unmarshal error: %w", err)
	}

	log.Printf("Created new bouncer '%s'.\n", BouncerName)
	return resp.ApiKey, nil
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
		return fmt.Errorf("error deleting bouncer: %w, output: %s", err, string(out))
	}
	return nil
}
