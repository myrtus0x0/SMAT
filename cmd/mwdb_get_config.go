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
	Long:  `returns all config details for the sha256 hashes passed`,
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
