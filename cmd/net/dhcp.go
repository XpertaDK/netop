package main

import (
	"os"

	"github.com/angelfreak/net/pkg/types"
	"github.com/spf13/cobra"
)

var dhcpServerCmd = &cobra.Command{
	Use:   "dhcp [start|stop|status]",
	Short: "Run a DHCP server (useful for sharing connection via ethernet)",
	Long: `Start a DHCP server to assign IP addresses to connected devices.

Useful when sharing your connection via ethernet cable.

Examples:
  net dhcp                              Show status
  net dhcp start                        Start with defaults
  net dhcp start --gateway 10.0.0.1     Custom gateway
  net dhcp stop                         Stop the server`,
	Run: func(cmd *cobra.Command, args []string) {
		action := "status"
		if len(args) > 0 {
			action = args[0]
		}

		var config *types.DHCPServerConfig
		if action == "start" {
			// Get configuration from flags or use defaults
			gateway, _ := cmd.Flags().GetString("gateway")
			ipRange, _ := cmd.Flags().GetString("ip-range")
			dnsServers, _ := cmd.Flags().GetStringSlice("dns")
			leaseTime, _ := cmd.Flags().GetString("lease-time")

			// Set defaults if not provided
			if gateway == "" {
				gateway = "192.168.100.1"
			}
			if ipRange == "" {
				ipRange = "192.168.100.50,192.168.100.150"
			}
			if len(dnsServers) == 0 {
				dnsServers = []string{"8.8.8.8", "8.8.4.4"}
			}
			if leaseTime == "" {
				leaseTime = "12h"
			}

			config = &types.DHCPServerConfig{
				Interface: iface,
				Gateway:   gateway,
				IPRange:   ipRange,
				DNS:       dnsServers,
				LeaseTime: leaseTime,
			}
		}

		if err := createApp().RunDHCPServer(action, config); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	dhcpServerCmd.Flags().String("gateway", "192.168.100.1", "Gateway IP address")
	dhcpServerCmd.Flags().String("ip-range", "192.168.100.50,192.168.100.150", "DHCP IP range")
	dhcpServerCmd.Flags().StringSlice("dns", []string{"8.8.8.8", "8.8.4.4"}, "DNS servers")
	dhcpServerCmd.Flags().String("lease-time", "12h", "DHCP lease time (e.g., 12h, 24h)")

	rootCmd.AddCommand(dhcpServerCmd)
}
