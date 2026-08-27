package vpn

import (
	"fmt"
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestConnectNetBird_MissingBinary(t *testing.T) {
	executor := &mockSystemExecutor{
		hasCommandOverride: map[string]bool{"netbird": false},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {Type: "netbird"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("nb")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "netbird")
	assert.Contains(t, err.Error(), "install")
}

func TestConnectNetBird_Success(t *testing.T) {
	tmpDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"netbird up --setup-key-file " + tmpDir + "/netbird-setupkey --management-url https://api.netbird.io --disable-dns": "",
			"netbird status --json": `{"daemonStatus":"Connected"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {
				Type:          "netbird",
				SetupKey:      "XXXXXXXX",
				ManagementURL: "https://api.netbird.io",
			},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tmpDir)

	err := manager.Connect("nb")
	assert.NoError(t, err)
	// The setup key must be passed via --setup-key-file, never as an argv token.
	executor.assertCommandExecuted(t, "netbird up --setup-key-file "+tmpDir+"/netbird-setupkey --management-url https://api.netbird.io --disable-dns")
	for _, cmd := range executor.executedCommands {
		assert.NotContains(t, cmd, "--setup-key XXXXXXXX", "setup key must never appear in a command argument")
	}
}

func TestConnectNetBird_NoSetupKey(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":    "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connected"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {Type: "netbird"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("nb")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "netbird up --disable-dns")
}

func TestConnectNetBird_WithProfile(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":       "default via 192.168.1.1 dev eth0",
			"netbird profile select work": "Profile switched successfully to: work",
			"netbird up --disable-dns":    "",
			"netbird status --json":       `{"daemonStatus":"Connected"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-nb": {
				Type:    "netbird",
				Profile: "work",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("work-nb")
	assert.NoError(t, err)

	executor.assertCommandExecuted(t, "netbird profile select work")
	executor.assertCommandExecuted(t, "netbird up --disable-dns")
}

func TestConnectNetBird_ProfileSelectFailureIsFatal(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":    "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connected"}`,
		},
		errors: map[string]error{
			"netbird profile select missing": fmt.Errorf("command failed: exit status 1 (stderr: profile not found)"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-nb": {
				Type:    "netbird",
				Profile: "missing",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("work-nb")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "profile")

	executor.assertCommandExecuted(t, "netbird profile select missing")
	// Connecting without the requested profile would silently use the wrong
	// account, so "up" must not run after a failed profile select.
	executor.assertCommandNotExecuted(t, "netbird up --disable-dns")
}

func TestConnectNetBird_FailsWhenTunnelNeverConnects(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":    "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connecting"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {Type: "netbird"},
		},
	}
	manager := NewManager(executor, logger, configMgr)
	manager.verifyAttempts = 2
	manager.verifyDelay = 0

	err := manager.Connect("nb")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "did not come up")
}

func TestListVPNs_NetBirdRunning(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":            "",
			"ip link show type wireguard": "",
			"tailscale status --json":     "",
			"netbird status --json":       `{"daemonStatus":"Connected"}`,
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"my-nb": {Type: "netbird"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 1)
	assert.Equal(t, "my-nb", vpns[0].Name)
	assert.True(t, vpns[0].Connected)
	assert.Equal(t, "wt0", vpns[0].Interface)
}

func TestNetBird_ConnectDisconnectCycle(t *testing.T) {
	tempDir := t.TempDir()

	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":    "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connected"}`,
			"netbird down":             "",
			"ip route show":            "default via 192.168.1.1 dev eth0",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {Type: "netbird"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	// Connect
	err := manager.Connect("nb")
	assert.NoError(t, err)

	// Verify state file
	state := manager.getActiveVPNState()
	assert.NotNil(t, state)
	assert.Equal(t, "nb", state.Name)
	assert.Equal(t, "netbird", state.Type)
	assert.Equal(t, "wt0", state.Interface)

	// Disconnect
	err = manager.Disconnect("nb")
	assert.NoError(t, err)

	// Verify state file cleared
	state = manager.getActiveVPNState()
	assert.Nil(t, state)

	// Verify netbird down was called
	executor.assertCommandExecuted(t, "netbird down")
}

func TestDisconnectNetBird_Tracked(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"netbird down": "",
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger}

	state := &vpnState{Type: "netbird", Interface: "wt0"}
	manager.disconnectTracked(state)

	executor.assertCommandExecuted(t, "netbird down")
}

func TestDisconnectNetBird_FailureKeepsState(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		errors: map[string]error{
			"netbird down": fmt.Errorf("daemon wedged"),
		},
	}
	logger := &mockLogger{}
	manager := NewManagerWithDir(executor, logger, &mockConfigManager{}, tempDir)

	err := manager.setActiveVPNState(vpnState{
		Name:              "nb",
		Interface:         "wt0",
		Type:              "netbird",
		OriginalGateway:   "192.168.1.1",
		OriginalInterface: "eth0",
	})
	assert.NoError(t, err)

	err = manager.Disconnect("nb")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to disconnect NetBird")

	// State must be retained so the user can retry the stop.
	assert.Equal(t, "nb", manager.getActiveVPN())
	// Routes must be left untouched while the tunnel is still up.
	executor.assertCommandNotExecuted(t, "ip route replace default via 192.168.1.1 dev eth0")
}

func TestNetBirdConfigFields(t *testing.T) {
	config := types.VPNConfig{
		Type:          "netbird",
		SetupKey:      "XXXXXXXX",
		ManagementURL: "https://api.netbird.io",
	}
	assert.Equal(t, "netbird", config.Type)
	assert.Equal(t, "XXXXXXXX", config.SetupKey)
	assert.Equal(t, "https://api.netbird.io", config.ManagementURL)
}

func TestConnect_KeepsStateWhenExistingVPNTeardownFails(t *testing.T) {
	// A wedged daemon must not let a new Connect wipe the old VPN's state:
	// the tunnel may still be up and would become untracked.
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
		},
		errors: map[string]error{
			"netbird down": fmt.Errorf("daemon not responding"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"other": {Type: "wireguard", Config: "wireguard config"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	err := manager.setActiveVPNState(vpnState{Name: "old-nb", Type: "netbird", Interface: "wt0"})
	assert.NoError(t, err)

	err = manager.Connect("other")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot disconnect active VPN")
	assert.Equal(t, "old-nb", manager.getActiveVPN(), "old VPN state must be retained")
}

// TestListVPNs_ProfileDisambiguatesNetBird covers the case the typeCount
// guard is too blunt for: two NetBird configs that DO name distinct
// profiles are not ambiguous, because the daemon reports which profile is
// active. Only the entry whose profile is active may show connected.
func TestListVPNs_ProfileDisambiguatesNetBird(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Connected"}`,
			"netbird profile list": "NAME     ACTIVE\n" +
				"wendy\n" +
				"vesperx  ✓\n",
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"wendy-net":   {Type: "netbird", Profile: "wendy"},
			"vesperx-net": {Type: "netbird", Profile: "vesperx"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 2)

	byName := map[string]bool{}
	for _, v := range vpns {
		byName[v.Name] = v.Connected
	}
	assert.True(t, byName["vesperx-net"], "the entry whose profile is ACTIVE must report connected")
	assert.False(t, byName["wendy-net"], "an inactive profile must not report connected")
}

// When the daemon is down, no profile reports connected even though one is
// still marked ACTIVE — ACTIVE means "selected", not "up".
func TestListVPNs_ActiveProfileDownNotConnected(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Disconnected"}`,
			"netbird profile list":    "NAME     ACTIVE\nwendy\nvesperx  ✓\n",
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"wendy-net":   {Type: "netbird", Profile: "wendy"},
			"vesperx-net": {Type: "netbird", Profile: "vesperx"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	for _, v := range vpns {
		assert.False(t, v.Connected, "daemon down: %q must not report connected", v.Name)
	}
}

// Falling back to the old conservative behavior when "profile list" is
// unavailable (older CLI, permission error) must not regress: neither
// profile-less entry may be flagged connected.
func TestListVPNs_ProfileListUnavailableStaysConservative(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Connected"}`,
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
			"netbird profile list":    fmt.Errorf("unknown command"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"wendy-net":   {Type: "netbird", Profile: "wendy"},
			"vesperx-net": {Type: "netbird", Profile: "vesperx"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	for _, v := range vpns {
		assert.False(t, v.Connected, "no profile info: %q must not be flagged connected", v.Name)
	}
}

func TestNetBirdActiveProfile(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"checkmark", "NAME     ACTIVE\nwendy\nvesperx  ✓\n", "vesperx"},
		{"first is active", "NAME     ACTIVE\nwendy    ✓\nvesperx\n", "wendy"},
		{"single default", "NAME     ACTIVE\ndefault  ✓\n", "default"},
		{"none active", "NAME     ACTIVE\nwendy\nvesperx\n", ""},
		// Regression: a row having a second column is not proof of being
		// active. With an extra STATUS column, matching on column presence
		// alone returned the first profile listed.
		{"extra status column", "NAME     ACTIVE   STATUS\nwendy             idle\nvesperx  \u2713        up\n", "vesperx"},
		{"extra column none active", "NAME     ACTIVE   STATUS\nwendy             idle\nvesperx           up\n", ""},
		{"asterisk marker", "NAME     ACTIVE\nwendy\nvesperx  *\n", "vesperx"},
		// Shapes observed from netbird 0.76.0 on a real multi-profile host.
		// Inactive rows carry a trailing-whitespace ACTIVE column, so they
		// yield a single field and must not be mistaken for active.
		{"real: single profile none active", "NAME     ACTIVE\ndefault  \n", ""},
		{"real: middle profile active", "NAME     ACTIVE\ndefault  \nvesperx  \u2713\nwendy    \n", "vesperx"},
		{"real: last profile active", "NAME     ACTIVE\ndefault  \nvesperx  \nwendy    \u2713\n", "wendy"},
		{"empty", "", ""},
		{"header only", "NAME     ACTIVE\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, netBirdActiveProfile(tt.output))
		})
	}
}
