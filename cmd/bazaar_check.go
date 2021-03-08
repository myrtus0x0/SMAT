package cmd

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	mbazar "github.com/vertoforce/go-malwarebazaar"
)

func init() {
	bazaarCmd.AddCommand(checkCmd)
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "checks if a sample exists within MalwareBazaar",
	Long: `Same functionality provided as the urlhaus_check command. Will tell you if the sample is already in the MalwareBazaar dataset.
Format:
	
	smat bazaar check malware_samples...

Example usage:

	smat bazaar check qakbot_sample_1
	smat bazaar check qakbot_sample_1 emotet_sample_1`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		for _, hash := range args {
			entries, err := mbazar.QueryHash(ctx, hash)
			if err != nil {
				log.Warnf("unable to find sample: %s", err)
				continue
			}

			for _, entry := range entries {
				log.WithFields(log.Fields{
					"MD5":       entry.Md5Hash,
					"SHA256":    entry.Sha256Hash,
					"Delivery":  entry.DeliveryMethod,
					"Filename":  entry.FileName,
					"File size": entry.FileSize,
				}).Infof("sample found %s", hash)
			}
		}

	},
}
