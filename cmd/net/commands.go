package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// getNetworkNames returns a list of all network names from the config for completion
func getNetworkNames() []string {
	// Determine config file path
	configFile := configPath
	if configFile == "" {
		// Use default path
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		// Handle SUDO_USER for sudo execution
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
			home = "/home/" + sudoUser
		}
		configFile = home + "/.net/config.yaml"
	}

	// Read the config file to get all top-level keys
	file, err := os.ReadFile(configFile)
	if err != nil {
		return nil
	}

	var networks []string
	allKeys := make(map[string]bool)

	lines := strings.Split(string(file), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Check if this is a top-level key (no leading whitespace in original line)
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && strings.Contains(line, ":") {
			key := strings.TrimSpace(strings.Split(line, ":")[0])
			// Skip special sections
			if key != "common" && key != "ignored" && key != "vpn" {
				allKeys[key] = true
			}
		}
	}

	for key := range allKeys {
		networks = append(networks, key)
	}

	return networks
}

// printConnectionInfo displays the current connection information for the given interface
func printConnectionInfo(iface string) {
	conn, err := netMgr.GetConnectionInfo(iface)
	if err != nil {
		logger.Warn("Failed to retrieve connection info", "error", err)
		return
	}

	// Print connection success message with details
	fmt.Println("✓ Connected successfully")

	if conn.SSID != "" {
		fmt.Printf("  SSID:     %s\n", conn.SSID)
	}

	if conn.IP != nil {
		fmt.Printf("  IP:       %s\n", conn.IP.String())
	}

	if conn.Gateway != nil {
		fmt.Printf("  Gateway:  %s\n", conn.Gateway.String())
	}

	if len(conn.DNS) > 0 {
		fmt.Printf("  DNS:      ")
		for i, dns := range conn.DNS {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s", dns.String())
		}
		fmt.Println()
	}

	fmt.Println()
}

// connectVPN connects to VPN if configured for the network
func connectVPN(networkName string) {
	// Get network config to find VPN
	config, err := cfgManager.GetNetworkConfig(networkName)
	if err != nil {
		logger.Debug("No network config found for VPN check", "network", networkName)
		return
	}

	// Merge with common settings to get default VPN if not specified
	merged := cfgManager.MergeWithCommon(networkName, config)

	if merged.VPN == "" {
		logger.Debug("No VPN configured for network", "network", networkName)
		return
	}

	logger.Info("Connecting to VPN", "vpn", merged.VPN)
	err = vpnMgr.Connect(merged.VPN)
	if err != nil {
		logger.Error("Failed to connect to VPN", "vpn", merged.VPN, "error", err)
		fmt.Fprintf(os.Stderr, "✗ VPN connection failed (%s): %v\n", merged.VPN, err)
	} else {
		fmt.Printf("✓ VPN connected (%s)\n", merged.VPN)
	}
}

// installCompletion installs the completion script to the appropriate system location
func installCompletion(shell string, cmd *cobra.Command) {
	var installPath string
	var content strings.Builder

	// Generate completion script
	switch shell {
	case "bash":
		cmd.Root().GenBashCompletion(&content)
		// Check common bash completion directories
		if _, err := os.Stat("/etc/bash_completion.d"); err == nil {
			installPath = "/etc/bash_completion.d/net"
		} else if _, err := os.Stat("/usr/local/etc/bash_completion.d"); err == nil {
			installPath = "/usr/local/etc/bash_completion.d/net"
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: No bash completion directory found.\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "Please install manually: net completion bash > /path/to/completion/dir/net\n")
			return
		}
	case "zsh":
		cmd.Root().GenZshCompletion(&content)
		// Try to find zsh completion directory
		homeDir, _ := os.UserHomeDir()
		installPath = homeDir + "/.local/share/zsh/site-functions/_net"
		// Create directory if it doesn't exist
		os.MkdirAll(homeDir+"/.local/share/zsh/site-functions", 0755)
	case "fish":
		cmd.Root().GenFishCompletion(&content, true)
		homeDir, _ := os.UserHomeDir()
		installPath = homeDir + "/.config/fish/completions/net.fish"
		// Create directory if it doesn't exist
		os.MkdirAll(homeDir+"/.config/fish/completions", 0755)
	case "powershell":
		fmt.Fprintf(cmd.ErrOrStderr(), "PowerShell completion installation not supported.\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "Please install manually: net completion powershell > net.ps1\n")
		return
	default:
		fmt.Fprintf(cmd.ErrOrStderr(), "Unsupported shell: %s\n", shell)
		return
	}

	// Check if we need sudo for system directories
	needsSudo := strings.HasPrefix(installPath, "/etc/") || strings.HasPrefix(installPath, "/usr/")

	if needsSudo {
		// Try to install with sudo
		fmt.Fprintf(cmd.ErrOrStderr(), "Installing completion script to %s (requires sudo)...\n", installPath)

		// Create temp file
		tmpFile, err := os.CreateTemp("", "net-completion-*")
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error creating temp file: %v\n", err)
			return
		}
		defer os.Remove(tmpFile.Name())

		// Write completion script to temp file
		_, err = tmpFile.WriteString(content.String())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error writing to temp file: %v\n", err)
			return
		}
		tmpFile.Close()

		// Use sudo to copy to final location
		_, err = sysExecutor.Execute("sudo", "cp", tmpFile.Name(), installPath)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error installing completion script: %v\n", err)
			fmt.Fprintf(cmd.ErrOrStderr(), "Please install manually: sudo net completion %s > %s\n", shell, installPath)
			return
		}
	} else {
		// Install directly to user directory
		fmt.Fprintf(cmd.ErrOrStderr(), "Installing completion script to %s...\n", installPath)

		file, err := os.Create(installPath)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error creating completion file: %v\n", err)
			return
		}
		defer file.Close()

		_, err = file.WriteString(content.String())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error writing completion script: %v\n", err)
			return
		}
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "Completion script installed successfully!\n")

	// Print instructions for enabling completion
	switch shell {
	case "bash":
		fmt.Fprintf(cmd.ErrOrStderr(), "Restart your shell or run: source %s\n", installPath)
	case "zsh":
		fmt.Fprintf(cmd.ErrOrStderr(), "Add 'fpath=(~/.local/share/zsh/site-functions $fpath)' to your ~/.zshrc if not already present\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "Then restart your shell or run: autoload -U compinit && compinit\n")
	case "fish":
		fmt.Fprintf(cmd.ErrOrStderr(), "Restart your shell to enable completions\n")
	}
}
