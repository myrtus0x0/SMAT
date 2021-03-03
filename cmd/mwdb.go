package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(mwdbCmd)
}

var mwdbCmd = &cobra.Command{
	Use:   "mwdb",
	Short: "all subcommands relating to CERT.PLs MWDB platform",
	Long:  `all subcommands relating to CERT.PLs MWDB platform`,
}
