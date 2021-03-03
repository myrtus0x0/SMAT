package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(foxCmd)
}

var foxCmd = &cobra.Command{
	Use:   "fox",
	Short: "all subcommands relating to the threatfox platform",
	Long:  `all subcommands relating to the threatfox platform`,
}
