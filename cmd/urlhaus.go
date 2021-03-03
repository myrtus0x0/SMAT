package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(urlhausCmd)
}

var urlhausCmd = &cobra.Command{
	Use:   "urlhaus",
	Short: "all subcommands relating to the urlhaus platform",
	Long:  `all subcommands relating to the urlhaus platform`,
}
