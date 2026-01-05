// Package dhcpclient provides DHCP client functionality for obtaining network leases.
// This is distinct from pkg/dhcp which handles DHCP server operations for hotspot mode.
package dhcpclient

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/types"
)

// Manager implements the DHCPClientManager interface
type Manager struct {
	executor types.SystemExecutor
	logger   types.Logger
}

// NewManager creates a new DHCP client manager
func NewManager(executor types.SystemExecutor, logger types.Logger) *Manager {
	return &Manager{
		executor: executor,
		logger:   logger,
	}
}

// Acquire obtains a DHCP lease for the interface.
// hostname is optional - if provided, it will be sent in DHCP requests without changing system hostname.
func (m *Manager) Acquire(iface string, hostname string) error {
	m.logger.Info("Acquiring DHCP lease", "interface", iface)

	// Try udhcpc first (faster, ~1s vs 3-5s for dhclient)
	if m.executor.HasCommand("udhcpc") {
		m.logger.Debug("Using udhcpc for DHCP (faster)")
		return m.acquireUdhcpc(iface, hostname)
	}

	// Fall back to dhclient
	m.logger.Debug("Using dhclient for DHCP")
	return m.acquireDhclient(iface, hostname)
}

// Release stops any running DHCP client for the interface and cleans up lease files.
func (m *Manager) Release(iface string) error {
	m.logger.Debug("Releasing DHCP lease", "interface", iface)

	// Kill both DHCP clients to ensure cleanup
	m.executor.ExecuteWithTimeout(500*time.Millisecond, "pkill", "-9", "-f", "udhcpc.*"+iface)
	m.executor.ExecuteWithTimeout(500*time.Millisecond, "pkill", "-9", "-f", "dhclient.*"+iface)

	// Clean up lease files
	m.executor.ExecuteWithTimeout(500*time.Millisecond, "rm", "-f",
		"/var/lib/dhcp/dhclient."+iface+".leases",
		types.RuntimeDir+"/dhclient."+iface+".leases")

	return nil
}

// Renew renews the DHCP lease for the interface.
// For simplicity, this performs a fresh acquisition (same behavior as original implementation).
func (m *Manager) Renew(iface string, hostname string) error {
	m.logger.Info("Renewing DHCP lease", "interface", iface)
	return m.Acquire(iface, hostname)
}

// acquireUdhcpc uses udhcpc (BusyBox) for faster DHCP acquisition
func (m *Manager) acquireUdhcpc(iface string, hostname string) error {
	// Release any existing clients first
	m.Release(iface)

	// Build udhcpc command
	// -i: interface, -n: fail if no lease (don't go to background), -q: quit after obtaining lease
	args := []string{"-i", iface, "-n", "-q"}
	if hostname != "" {
		m.logger.Info("Sending hostname in DHCP request", "hostname", hostname)
		args = append(args, "-x", "hostname:"+hostname)
	}

	// 10 second timeout is plenty - udhcpc typically completes in 1-2 seconds
	_, err := m.executor.ExecuteWithTimeout(10*time.Second, "udhcpc", args...)
	if err != nil {
		return fmt.Errorf("udhcpc failed: %w", err)
	}

	m.logAcquiredIP(iface)
	return nil
}

// acquireDhclient uses dhclient (ISC) as fallback
func (m *Manager) acquireDhclient(iface string, hostname string) error {
	// Release any existing clients first
	m.Release(iface)

	// Build dhclient command with optional hostname via config file
	// 15s timeout is plenty - DHCP typically completes in 3-5s
	args := []string{"15", "dhclient", "-v"}
	if hostname != "" {
		m.logger.Info("Sending hostname in DHCP request", "hostname", hostname)
		// Create temporary dhclient.conf with hostname using atomic write with secure permissions
		confContent := fmt.Sprintf("send host-name \"%s\";\n", hostname)
		dhclientConf := types.RuntimeDir + "/dhclient.conf"
		if _, err := m.executor.ExecuteWithInput("install", confContent, "-m", "0600", "/dev/stdin", dhclientConf); err != nil {
			m.logger.Warn("Failed to create dhclient config", "error", err)
		} else {
			args = append(args, "-cf", dhclientConf)
		}
	}
	args = append(args, iface)

	// Start dhclient with timeout wrapper
	_, err := m.executor.Execute("timeout", args...)
	if err != nil {
		return fmt.Errorf("dhclient failed: %w", err)
	}

	m.logAcquiredIP(iface)
	return nil
}

// logAcquiredIP logs the IP address after successful DHCP
func (m *Manager) logAcquiredIP(iface string) {
	ipOutput, err := m.executor.ExecuteWithTimeout(2*time.Second, "ip", "addr", "show", iface)
	if err == nil {
		ip := m.parseIPAddress(ipOutput)
		if ip != nil {
			m.logger.Info("Address acquired", "ip", ip.String())
		}
	}
}

// parseIPAddress extracts the first IPv4 address from ip addr output
func (m *Manager) parseIPAddress(output string) net.IP {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip, _, err := net.ParseCIDR(parts[1])
				if err == nil {
					return ip
				}
			}
		}
	}
	return nil
}
