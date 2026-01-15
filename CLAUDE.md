# Claude Code Instructions for netop

## Project Goal

netop is a **lightweight, single-binary network manager for Linux** (binary name: `net`) that prioritizes:
- **Simplicity** - One YAML config file, one binary, no daemons
- **Privacy** - MAC randomization, hostname spoofing, VPN integration
- **Portability** - Works on minimal systems (Alpine, embedded Linux)
- **Transparency** - Direct control over wpa_supplicant, dhclient, wireguard

Target users: Power users who want full control over their network stack without NetworkManager/systemd-networkd complexity.

## Git Workflow

**Always create pull requests - never push directly to master.**

```bash
git checkout -b fix/descriptive-name
# make changes and commit
git push -u origin fix/descriptive-name
gh pr create --title "Fix: descriptive title" --body "Description"
```

### PR Self-Review Requirement

**After creating or pushing to a PR, always perform a self-review:**

1. Run `gh pr diff <PR#>` to review all changes
2. Look for:
   - Dead code or no-op implementations
   - Redundant helper functions (use stdlib when possible)
   - Deprecated function usage
   - Missing imports after refactoring
   - Inconsistent error handling
   - Package-level mutable state that could cause test issues
3. Fix any issues found and push follow-up commits
4. Only consider the PR ready after self-review passes

## Design Principles

### Architecture
- **Dependency injection** - All managers implement interfaces in `pkg/types/`
- **No singletons** - Pass dependencies explicitly for testability
- **Thin CLI layer** - `cmd/net/main.go` is just glue; logic lives in `pkg/`
- **Shell out to system tools** - Don't reinvent `ip`, `iw`, `wpa_supplicant`

### Code Style
- **Explicit over implicit** - No magic, no globals
- **Errors are values** - Return errors, don't panic
- **Test via interfaces** - Mock at interface boundaries
- **Minimal dependencies** - Only cobra, viper, logrus, testify

### Configuration
- **YAML with inheritance** - `common:` settings merge into network configs
- **Viper for parsing** - But be aware: `viper.IsSet()` returns false for null YAML values
- **Runtime files in /run/net/** - Not /tmp (security)

## Key Interfaces (pkg/types/types.go)

```go
ConfigManager   - Load/parse YAML config, merge with common
WiFiManager     - Scan, connect, disconnect via wpa_supplicant
VPNManager      - OpenVPN and WireGuard connections
NetworkManager  - DNS, MAC, IP, routes, DHCP
HotspotManager  - WiFi AP mode
DHCPManager     - DHCP server for hotspot
SystemExecutor  - Shell command execution with timeouts
Logger          - Structured logging
```

## Directory Structure

```
cmd/net/         - CLI entry point (cobra commands)
pkg/config/      - Viper-based YAML config loading
pkg/network/     - ip, route, resolv.conf management
pkg/wifi/        - wpa_supplicant control
pkg/vpn/         - OpenVPN and WireGuard
pkg/dhcp/        - dhclient/udhcpc wrapper
pkg/hotspot/     - hostapd + dnsmasq
pkg/system/      - Command execution, logging
pkg/types/       - Shared interfaces and types
```

## Testing

```bash
go test ./...              # Run all tests
go test -cover ./...       # With coverage
go test -v ./pkg/config/   # Verbose single package
```

### Test Patterns
- Use `testify/assert` for assertions
- Mock interfaces, not implementations
- Create temp files for config tests
- Tests must be deterministic (no timing dependencies)

## Building

```bash
go build -o net ./cmd/net                # Local build
GOOS=linux GOARCH=amd64 go build ...     # Cross-compile
```

## Running Without Sudo

Network operations require elevated privileges. Instead of running `sudo net` every time, you can:

### Option 1: Set capabilities on the binary (recommended)

```bash
sudo setcap 'cap_net_admin,cap_net_raw+ep' /usr/local/bin/net
```

This grants only the specific capabilities needed for network management.

### Option 2: Add sudo rule for net

Create `/etc/sudoers.d/net`:

```bash
sudo visudo -f /etc/sudoers.d/net
```

Add (replace `username` with your user):

```
username ALL=(ALL) NOPASSWD: /usr/local/bin/net
```

Then create an alias in your shell rc file:

```bash
alias net='sudo /usr/local/bin/net'
```

### Option 3: Run as root user

For dedicated network appliances or embedded systems, running as root may be acceptable.

### Capabilities Explained

`net` requires these Linux capabilities:
- `CAP_NET_ADMIN` - Configure network interfaces, routing, firewall
- `CAP_NET_RAW` - Use raw sockets (for some network operations)

## Common Gotchas

### Viper null detection
```go
// WRONG: viper.IsSet() returns false for `vpn:` (null)
if v.IsSet("network.vpn") { ... }

// RIGHT: Check raw map for key existence
networkMap := v.GetStringMap("network")
_, exists := networkMap["vpn"]
```

### Interface detection
- Ignore virtual interfaces (docker*, veth*, br*)
- Check `ignored.interfaces` regex patterns in config
- Prefer wireless over wired when both available

### DHCP clients
- Support both `dhclient` (Debian) and `udhcpc` (Alpine/BusyBox)
- Check which is available at runtime

## Open Issues to Consider

See: `gh issue list`

Key improvements planned:
- #4: Refactor main.go into separate command files
- #5: Consolidate DHCP logic
- #6: Increase CLI test coverage (currently ~20%)
- #10: Graceful shutdown handling
- #12: Structured logging levels

## Release Process

1. Ensure all tests pass: `go test ./...`
2. Create and push tag: `git tag v0.X.0 && git push --tags`
3. GitHub Actions builds binaries and creates release
4. Or manually: `gh release create v0.X.0 --generate-notes`
