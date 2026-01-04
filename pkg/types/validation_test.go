package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateInterfaceName(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		wantErr bool
	}{
		{"valid eth0", "eth0", false},
		{"valid wlan0", "wlan0", false},
		{"valid enp0s3", "enp0s3", false},
		{"valid with underscore", "eth_0", false},
		{"valid with dash", "eth-0", false},
		{"valid max length", "abcdefghijklmno", false},
		{"empty", "", true},
		{"too long", "abcdefghijklmnop", true},
		{"starts with number", "0eth", true},
		{"contains space", "eth 0", true},
		{"contains slash", "eth/0", true},
		{"contains semicolon", "eth;rm -rf", true},
		{"path traversal attempt", "../../../etc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInterfaceName(tt.iface)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateMAC(t *testing.T) {
	tests := []struct {
		name    string
		mac     string
		wantErr bool
	}{
		{"valid lowercase", "aa:bb:cc:dd:ee:ff", false},
		{"valid uppercase", "AA:BB:CC:DD:EE:FF", false},
		{"valid mixed", "Aa:Bb:Cc:Dd:Ee:Ff", false},
		{"empty", "", false},
		{"random keyword", "random", false},
		{"permanent keyword", "permanent", false},
		{"too short", "aa:bb:cc:dd:ee", true},
		{"too long", "aa:bb:cc:dd:ee:ff:00", true},
		{"wrong separator", "aa-bb-cc-dd-ee-ff", true},
		{"invalid hex", "gg:bb:cc:dd:ee:ff", true},
		{"no separator", "aabbccddeeff", true},
		{"injection attempt", "aa:bb:cc:dd:ee:ff;rm", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMAC(tt.mac)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSSID(t *testing.T) {
	tests := []struct {
		name    string
		ssid    string
		wantErr bool
	}{
		{"valid simple", "MyNetwork", false},
		{"valid with spaces", "My Network", false},
		{"valid with special chars", "My-Network_123!", false},
		{"valid max length", "12345678901234567890123456789012", false},
		{"empty", "", true},
		{"too long", "123456789012345678901234567890123", true},
		{"contains null", "My\x00Network", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSID(tt.ssid)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePSK(t *testing.T) {
	tests := []struct {
		name    string
		psk     string
		wantErr bool
	}{
		{"valid 8 chars", "password", false},
		{"valid 63 chars", "123456789012345678901234567890123456789012345678901234567890123", false},
		{"empty (open network)", "", false},
		{"too short", "pass", true},
		{"too long 64 chars", "1234567890123456789012345678901234567890123456789012345678901234", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePSK(tt.psk)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{"valid simple", "myhost", false},
		{"valid with dash", "my-host", false},
		{"valid with numbers", "host123", false},
		{"valid fqdn", "host.example.com", false},
		{"valid template", "prefix-<name>-suffix", false},
		{"empty", "", false},
		{"starts with dash", "-myhost", true},
		{"ends with dash", "myhost-", true},
		{"contains underscore", "my_host", true},
		{"contains space", "my host", true},
		{"label too long", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostname(tt.hostname)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid simple", "user", false},
		{"valid with underscore", "user_name", false},
		{"valid with dash", "user-name", false},
		{"valid with numbers", "user123", false},
		{"valid starts with underscore", "_user", false},
		{"empty", "", true},
		{"starts with dash", "-user", true},
		{"starts with number", "1user", true},
		{"contains space", "user name", true},
		{"path traversal", "../../../", true},
		{"too long", "abcdefghijklmnopqrstuvwxyz123456789", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
