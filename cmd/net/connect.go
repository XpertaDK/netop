package main

import (
	"os"

	"github.com/spf13/cobra"
)

var connectCmd = &cobra.Command{
	Use:   "connect <name|ssid> [password]",
	Short: "Connect to a configured network or WiFi SSID",
	Long: `Connect to a network by config name or WiFi SSID.

If <name> matches a network in ~/.net/config.yaml, uses that config.
Otherwise, treats it as a WiFi SSID and connects directly.

Examples:
  net connect home              Use "home" from config
  net connect CoffeeShop        Connect to SSID "CoffeeShop" (open)
  net connect CoffeeShop pass   Connect with password`,
	Args: cobra.RangeArgs(1, 2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getNetworkNames(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		password := ""
		if len(args) > 1 {
			password = args[1]
		}
		if err := createApp().RunConnect(name, password); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(connectCmd)
}
