package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(triageCmd)
}

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "all subcommands relating to the triage platform",
	Long:  `all subcommands relating to the triage platform`,
}
