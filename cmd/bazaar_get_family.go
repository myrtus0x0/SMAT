package cmd

import (
	"context"
	"io/ioutil"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	mbazar "github.com/vertoforce/go-malwarebazaar"
)

var (
	download bool
)

func init() {
	bazaarCmd.AddCommand(getFamilyCmd)
	getFamilyCmd.PersistentFlags().BoolVarP(&download, "download", "d", false, "used to download the samples")
}

var getFamilyCmd = &cobra.Command{
	Use:   "get_family",
	Short: "returns metadata for all samples uploaded for a family within the last 24 hours",
	Long: `Will print a log message for each malware sample in a specific family, showing the hash, the filename, delivery method and filesize. 
By default this call will only return a max of 50 samples. All samples can be downloaded via the download flag
Format:
	
	smat bazaar get_family malware_family...

Example usage:

	smat bazaar get_family qakbot 
	smat bazaar get_family qakbot -d`,
	Run: func(cmd *cobra.Command, args []string) {
		limit := 50

		for _, family := range args {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			entries, err := mbazar.QuerySignature(ctx, family, limit)
			if err != nil {
				log.Warnf("unable to find sample: %s", err)
				cancel()
				continue
			}
			cancel()

			if download {
				err := os.Mkdir(family, 0755)
				if err != nil {
					log.Error("unable to create family dir")
				}
			}

			for _, entry := range entries {
				firstSeenTime, err := time.Parse("2006-01-02 15:04:05", entry.FirstSeen)
				if err != nil {
					log.Error("unable to parse date time string %s", entry.FirstSeen)
					continue
				}

				if time.Now().Sub(firstSeenTime) < 24*time.Hour {
					log.WithFields(log.Fields{
						"MD5":        entry.Md5Hash,
						"SHA256":     entry.Sha256Hash,
						"Delivery":   entry.DeliveryMethod,
						"Filename":   entry.FileName,
						"File size":  entry.FileSize,
						"First seen": entry.FirstSeen,
					}).Infof("sample entry for family %s", family)

					if download {
						data, err := mbazar.Download(context.Background(), entry.Sha256Hash)
						if err != nil {
							log.Errorf("unable to download sample: %s", err)
						}

						decryptedData, err := mbazar.GetRawFile(data)
						if err != nil {
							log.Errorf("unable to decrypt sample: %s", err)
						}

						fileContents, err := ioutil.ReadAll(decryptedData)
						if err != nil {
							log.Errorf("unable to write sample: %s", err)
						}
						ioutil.WriteFile(family+"/"+entry.Sha256Hash, fileContents, 0644)
					}
				}
			}
		}
	},
}
