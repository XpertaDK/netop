package types

import (
	"fmt"
	"regexp"
	"strings"
)

// Validation regexes - compiled once at package init
var (
	// Interface names: start with letter, alphanumeric + underscore/dash, max 15 chars
	interfaceRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)

	// MAC address: 6 hex pairs separated by colons
	macRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

	// Hostname: RFC 1123 compliant
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

	// Username: Linux username format
	usernameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// ValidateInterfaceName validates a network interface name
func ValidateInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("interface name cannot be empty")
	}
	if len(name) > 15 {
		return fmt.Errorf("interface name too long (max 15 characters)")
	}
	if !interfaceRegex.MatchString(name) {
		return fmt.Errorf("invalid interface name: must start with letter, contain only alphanumeric, underscore, or dash")
	}
	return nil
}

// ValidateMAC validates a MAC address format
func ValidateMAC(mac string) error {
	if mac == "" {
		return nil // Empty is allowed (means don't change)
	}
	// Special values
	if mac == "random" || mac == "permanent" {
		return nil
	}
	if !macRegex.MatchString(mac) {
		return fmt.Errorf("invalid MAC address format: expected XX:XX:XX:XX:XX:XX")
	}
	return nil
}

// ValidateSSID validates a WiFi SSID
func ValidateSSID(ssid string) error {
	if ssid == "" {
		return fmt.Errorf("SSID cannot be empty")
	}
	if len(ssid) > 32 {
		return fmt.Errorf("SSID too long (max 32 bytes)")
	}
	if strings.ContainsAny(ssid, "\x00") {
		return fmt.Errorf("SSID cannot contain null bytes")
	}
	return nil
}

// ValidatePSK validates a WiFi password/PSK
func ValidatePSK(psk string) error {
	if psk == "" {
		return nil // Open network
	}
	if len(psk) < 8 {
		return fmt.Errorf("PSK too short (minimum 8 characters)")
	}
	if len(psk) > 63 {
		return fmt.Errorf("PSK too long (maximum 63 characters)")
	}
	return nil
}

// ValidateHostname validates a hostname (RFC 1123)
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return nil // Empty is allowed
	}
	// Allow template placeholders
	if strings.Contains(hostname, "<name>") {
		// Validate the parts around the template
		parts := strings.Split(hostname, "<name>")
		for _, part := range parts {
			if part != "" && !hostnameRegex.MatchString(strings.Trim(part, "-")) {
				return fmt.Errorf("invalid hostname format around template")
			}
		}
		return nil
	}
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}
	// Check each label
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("hostname label too long (max 63 characters)")
		}
		if !hostnameRegex.MatchString(label) {
			return fmt.Errorf("invalid hostname format: must be alphanumeric with dashes")
		}
	}
	return nil
}

// ValidateUsername validates a Linux username
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username format")
	}
	return nil
}

// ValidateDNSServer validates a DNS server address
func ValidateDNSServer(server string) error {
	if server == "" {
		return fmt.Errorf("DNS server cannot be empty")
	}
	// Already validated by net.ParseIP in the caller, but double-check
	if ip := parseIP(server); ip == nil {
		return fmt.Errorf("invalid DNS server IP address: %s", server)
	}
	return nil
}

// parseIP is a helper to parse IP addresses
func parseIP(s string) []byte {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return parseIPv4(s)
		case ':':
			return parseIPv6(s)
		}
	}
	return nil
}

func parseIPv4(s string) []byte {
	var p [4]byte
	for i := 0; i < 4; i++ {
		if len(s) == 0 {
			return nil
		}
		if i > 0 {
			if s[0] != '.' {
				return nil
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 255 {
			return nil
		}
		s = s[c:]
		p[i] = byte(n)
	}
	if len(s) != 0 {
		return nil
	}
	return p[:]
}

func parseIPv6(s string) []byte {
	// Simplified - just check if it looks valid
	if len(s) < 2 {
		return nil
	}
	// Accept any IPv6-looking string for now
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':') {
			return nil
		}
	}
	return []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} // placeholder
}

func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= 0xFFFFFF {
			return 0, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}
