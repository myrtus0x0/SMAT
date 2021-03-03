package cmd

import (
	"github.com/spf13/cobra"
)

var (
	// Used for flags.
	cfgFile     string
	userLicense string

	rootCmd = &cobra.Command{
		Use:   "smat",
		Short: "The Superior Malware Analysis Tool",
		Long:  `SMAT allows for anaylysts to quickly extract information about malware families, download samples, upload samples, download pcaps and extract config details from common malware families.`,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
