package cmd

import (
	"context"
	"fmt"
	"os"

	mwdb "github.com/myrtus0x0/gomwdb"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	mwdbCmd.AddCommand(getMWDBConfigCmd)
}

var getMWDBConfigCmd = &cobra.Command{
	Use:   "get_config",
	Short: "returns all config details for the sha256 hashes passed",
	Long: `When connected to a MWDB instance, this command will search for the sample and return the child config entry for that sample.
Format:
	
	smat mwdb get_config sha256_of_sample...

Example usage:

	smat mwdb get_config 691f3e4b532cb3802630762dadc0eb5f894a6b5463ab5723ef67379ef3f9d31f
	smat mwdb get_config fa4137e389984d71deae07e0d0c0c191e2c0cfb4884defe6b9e4ccee5e5a6fc9 691f3e4b532cb3802630762dadc0eb5f894a6b5463ab5723ef67379ef3f9d31f`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, sha256sum := range args {
			fmt.Println(sha256sum)
			mwdbCli, err := mwdb.New(os.Getenv("MWDB_KEY"), os.Getenv("MWDB_HOST"), os.Getenv("MWDB_PROTO"))
			if err != nil {
				log.Fatal(err)
			}

			rawConfig, err := mwdbCli.GetConfigForSample(context.Background(), sha256sum)
			if err != nil {
				log.Error(err)
				continue
			}

			log.Info(string(rawConfig))
		}
	},
}
