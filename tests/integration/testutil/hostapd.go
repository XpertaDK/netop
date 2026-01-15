//go:build integration

package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestAPConfig holds configuration for a test access point.
type TestAPConfig struct {
	SSID       string
	PSK        string // Empty for open network
	Channel    int    // Default: 1
	HWMode     string // Default: "g" (2.4GHz)
	Hidden     bool   // Hidden SSID
	WPAVersion int    // 2 for WPA2, 3 for WPA3 (default: 2)
}

// TestAP represents a running test access point using hostapd.
type TestAP struct {
	Config    TestAPConfig
	Radio     *HWSimRadio
	Interface string
	cmd       *exec.Cmd
	confFile  string
	t         *testing.T
}

// StartTestAP starts a test access point on the given radio.
func StartTestAP(t *testing.T, radio *HWSimRadio, cfg TestAPConfig) *TestAP {
	t.Helper()
	SkipIfNotRoot(t)
	SkipIfMissingCmd(t, "hostapd")

	// Apply defaults
	if cfg.Channel == 0 {
		cfg.Channel = 1
	}
	if cfg.HWMode == "" {
		cfg.HWMode = "g"
	}
	if cfg.WPAVersion == 0 {
		cfg.WPAVersion = 2
	}

	ap := &TestAP{
		Config:    cfg,
		Radio:     radio,
		Interface: radio.Interface,
		t:         t,
	}

	// Set interface to AP mode
	if err := SetInterfaceMode(t, radio.Interface, "ap"); err != nil {
		// Try __ap mode as fallback (some systems use this)
		if err2 := SetInterfaceMode(t, radio.Interface, "__ap"); err2 != nil {
			t.Fatalf("failed to set AP mode: %v (also tried __ap: %v)", err, err2)
		}
	}

	// Generate hostapd config
	confContent := ap.generateConfig()

	// Write config to temp file
	confFile, err := os.CreateTemp("", "hostapd-*.conf")
	if err != nil {
		t.Fatalf("failed to create hostapd config file: %v", err)
	}
	ap.confFile = confFile.Name()

	if _, err := confFile.WriteString(confContent); err != nil {
		confFile.Close()
		os.Remove(confFile.Name())
		t.Fatalf("failed to write hostapd config: %v", err)
	}
	confFile.Close()

	// Start hostapd
	ap.cmd = exec.Command("hostapd", ap.confFile)
	if err := ap.cmd.Start(); err != nil {
		os.Remove(ap.confFile)
		t.Fatalf("failed to start hostapd: %v", err)
	}

	// Register cleanup
	t.Cleanup(ap.Stop)

	// Wait for AP to be ready
	time.Sleep(1 * time.Second)

	// Verify hostapd is still running
	if ap.cmd.ProcessState != nil && ap.cmd.ProcessState.Exited() {
		t.Fatalf("hostapd exited unexpectedly")
	}

	t.Logf("Started test AP: SSID=%s, Interface=%s, Channel=%d", cfg.SSID, radio.Interface, cfg.Channel)

	return ap
}

// generateConfig generates hostapd configuration content.
func (ap *TestAP) generateConfig() string {
	cfg := ap.Config

	config := fmt.Sprintf(`interface=%s
driver=nl80211
ssid=%s
hw_mode=%s
channel=%d
ieee80211n=1
wmm_enabled=1
`, ap.Interface, cfg.SSID, cfg.HWMode, cfg.Channel)

	if cfg.Hidden {
		config += "ignore_broadcast_ssid=1\n"
	}

	if cfg.PSK != "" {
		// WPA2/WPA3 configuration
		config += fmt.Sprintf(`auth_algs=1
wpa=%d
wpa_key_mgmt=WPA-PSK
wpa_passphrase=%s
`, cfg.WPAVersion, cfg.PSK)

		if cfg.WPAVersion == 2 {
			config += "rsn_pairwise=CCMP\n"
		} else if cfg.WPAVersion == 3 {
			config += "rsn_pairwise=CCMP\nwpa_key_mgmt=SAE\nieee80211w=2\n"
		}
	} else {
		// Open network
		config += "auth_algs=1\n"
	}

	return config
}

// Stop stops the test access point.
func (ap *TestAP) Stop() {
	if ap.cmd != nil && ap.cmd.Process != nil {
		_ = ap.cmd.Process.Kill()
		_ = ap.cmd.Wait()
	}

	if ap.confFile != "" {
		_ = os.Remove(ap.confFile)
	}

	// Reset interface mode back to managed
	_ = exec.Command("ip", "link", "set", ap.Interface, "down").Run()
	_ = exec.Command("iw", "dev", ap.Interface, "set", "type", "managed").Run()
	_ = exec.Command("ip", "link", "set", ap.Interface, "up").Run()
}

// GetBSSID returns the BSSID (MAC address) of the access point.
func (ap *TestAP) GetBSSID() (string, error) {
	output, err := exec.Command("iw", "dev", ap.Interface, "info").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get AP info: %v", err)
	}

	// Parse the addr field from iw output
	// Format: "addr XX:XX:XX:XX:XX:XX"
	lines := string(output)
	for _, line := range splitLines(lines) {
		if contains(line, "addr ") {
			parts := splitFields(line)
			for i, part := range parts {
				if part == "addr" && i+1 < len(parts) {
					return parts[i+1], nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find BSSID in output")
}

// IsRunning checks if hostapd is still running.
func (ap *TestAP) IsRunning() bool {
	if ap.cmd == nil || ap.cmd.Process == nil {
		return false
	}
	// Check if process has exited
	return ap.cmd.ProcessState == nil || !ap.cmd.ProcessState.Exited()
}

// helper functions to avoid importing strings package
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitFields(s string) []string {
	var fields []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				fields = append(fields, s[start:i])
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		fields = append(fields, s[start:])
	}
	return fields
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
