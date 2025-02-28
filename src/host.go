package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func setupHostDependencies() error {
	log.Println("[HOST-SETUP] Installing host dependencies: iptables-persistent netfilter-persistent...")
	if output, err := executeOnHost("apt-get", "update"); err != nil {
		return fmt.Errorf("apt-get update failed: %w, output: %s", err, output)
	}
	if output, err := executeOnHost("apt-get", "install", "-y", "-qq", "iptables-persistent", "netfilter-persistent"); err != nil {
		return fmt.Errorf("apt-get install failed: %w, output: %s", err, output)
	}
	log.Println("[HOST-SETUP] Host dependencies installed successfully.")
	return nil
}

func executeOnHost(command ...string) (string, error) {
	cmdArgs := []string{"run", "--rm",
		"--network", "host",
		"--pid", "host",
		"--privileged",
		"--ipc", "host",
		"-v", "/:/host",
		"alpine", "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "--"}
	cmdArgs = append(cmdArgs, command...)
	cmd := exec.Command("docker", cmdArgs...)
	output, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if err != nil {
		return outStr, fmt.Errorf("executeOnHost failed: %w, output: %s", err, outStr)
	}
	return outStr, nil
}

func persistIptablesRules() {
	persist := strings.ToLower(os.Getenv("PERSIST_IPTABLES")) == "true"
	if !persist {
		return
	}
	output, err := executeOnHost("netfilter-persistent", "save")
	if err != nil {
		log.Printf("[ERROR] Persisting iptables rules on HOST: %v | Output: %s", err, output)
	} else {
		log.Printf("[SUCCESS] Persisted iptables rules Host-side.")
	}
}
