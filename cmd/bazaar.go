package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(bazaarCmd)
}

var bazaarCmd = &cobra.Command{
	Use:   "bazaar",
	Short: "all subcommands relating to the malware bazaar platform",
	Long:  `all subcommands relating to the malware bazaar platform`,
}
