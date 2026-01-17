package main

import (
	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script for your shell",
	Long: `Generate completion script for your shell.

By default, this command outputs the completion script to stdout.
Use the output in your shell configuration or install it to the system location.

Examples:

  # Load bash completion in current session
  $ source <(net completion bash)

  # Install bash completion for all sessions
  $ sudo net completion bash --install

  # Add to your bashrc to load on every shell startup
  $ echo 'source <(net completion bash)' >> ~/.bashrc

  # Install zsh completion
  $ sudo net completion zsh --install

  # Install fish completion
  $ sudo net completion fish --install

After installation, restart your shell to enable tab completion for 'net' commands.

`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		shell := args[0]
		install, _ := cmd.Flags().GetBool("install")

		if install {
			// Install completion script to system location
			installCompletion(shell, cmd)
			return
		}

		// Default behavior: print to stdout
		switch shell {
		case "bash":
			cmd.Root().GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			cmd.Root().GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
		case "powershell":
			cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
		}
	},
}

func init() {
	completionCmd.Flags().Bool("install", false, "Install completion script to system location")

	rootCmd.AddCommand(completionCmd)
}
