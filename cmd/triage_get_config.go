package cmd

import (
	"context"
	"fmt"
	"os"

	triage "github.com/hatching/triage/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var file string

func init() {
	triageCmd.AddCommand(getConfigCmd)
	getFamilyCmd.PersistentFlags().StringVarP(&file, "file", "f", "", "used to download the samples")
}

var getConfigCmd = &cobra.Command{
	Use:   "get_config",
	Short: "returns all config details for the malware if it exists",
	Long:  `returns all config details for the malware if it exists`,
	Run: func(cmd *cobra.Command, args []string) {
		client := triage.NewClientWithRootURL(os.Getenv("TRIAGE_KEY"), triageAPI)
		for _, family := range args {
			seenC2s := map[string]bool{}
			sampleChan := client.Search(context.Background(), fmt.Sprintf("family:%s", family), 500)
			for sample := range sampleChan {
				log.Infof("pulling config for samples %s", sample.Filename)
				report, err := client.SampleOverviewReport(context.Background(), sample.ID)
				if err != nil {
					log.Errorf("unable to fetch report for %s", sample.ID)
					continue
				}
				for _, extracted := range report.Extracted {
					if extracted.Config.Attributes == nil || len(extracted.Config.C2) == 0 {
						continue
					}

					log.WithFields(log.Fields{
						"C2s":         extracted.Config.C2,
						"Crypto Keys": extracted.Config.Keys,
						"Version":     extracted.Config.Version,
						"Botnet":      extracted.Config.Botnet,
						"Attributes":  extracted.Config.Attributes,
					}).Info("printing config")

					for _, c2 := range extracted.Config.C2 {
						seenC2s[c2] = true
					}
				}
			}

			for c2 := range seenC2s {
				log.Infof("C2 for %s: %s", family, c2)
			}
		}
	},
}
