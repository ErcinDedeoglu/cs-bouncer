package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
)

type BouncerResponse struct {
	ApiKey string `json:"api_key"`
}

// CreateBouncerToken executes docker exec to generate a new token
func CreateBouncerToken(bouncerName, crowdsecContainer string) (string, error) {
	cmd := exec.Command("docker", "exec", crowdsecContainer, "cscli", "bouncers", "add", bouncerName, "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker exec error: %w, output: %s", err, string(out))
	}

	var resp BouncerResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", fmt.Errorf("unmarshal error: %w", err)
	}

	log.Printf("Created new CrowdSec API token for bouncer '%s'.\n", bouncerName)
	return resp.ApiKey, nil
}
