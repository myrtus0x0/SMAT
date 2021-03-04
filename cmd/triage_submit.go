package cmd

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	triage "github.com/hatching/triage/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	triageCmd.AddCommand(submitCmd)
}

const (
	triageAPI = "https://api.tria.ge"
)

var whitelistedSites = map[string]bool{
	"microsoft.com":     true,
	"www.microsoft.com": true,
}

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "submits a file to the Hatching triage platform",
	Long: `submit will upload a sample/samples to the Tria.ge platform and print out results for the uploads.
Information that can be printed is listed below:
	* Malware family
	* Network traffic details
	* Process information
	* Dumped payloads

Format:
	
	smat triage submit malware_samples...

Example usage:

	smat triage submit malware_sample1 
	smat triage submit malware_sample1 malware_sample2`,
	Run: func(cmd *cobra.Command, args []string) {
		client := triage.NewClientWithRootURL(os.Getenv("TRIAGE_KEY"), triageAPI)

		for _, filePath := range args {
			contents, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Errorf("unable to read file %s", filePath)
				return
			}

			sampleMD5 := fmt.Sprintf("%x", md5.Sum(contents))
			sample, err := client.SubmitSampleFile(context.Background(), sampleMD5, bytes.NewBuffer(contents), false, nil)
			if err != nil {
				log.Errorf("unable to submit sample to tria.ge: %s", err)
				return
			}
			log.Infof("submitted task for %s", filePath)

			// wait until the sample has been reported on
			for true {
				sample, err := client.SampleByID(context.Background(), sample.ID)
				if err != nil {
					log.Errorf("can't get sample status: %s", err)
					return
				}
				log.Infof("current task status: %s", sample.Status)
				if sample.Status == triage.SampleStatusReported {
					break
				} else {
					time.Sleep(time.Second * 15)
				}
			}

			log.Info("sample finished being processed")
			report, err := client.SampleOverviewReport(context.Background(), sample.ID)
			if err != nil {
				log.Info(report)
				log.Errorf("unable to get report from tria.ge: %s", err)
				return
			}

			log.WithFields(log.Fields{
				"Potential families": report.Analysis.Family,
				"Score":              report.Analysis.Score,
				"Tags":               report.Analysis.Tags,
			}).Info("finished analysis")

			for _, extracted := range report.Extracted {
				log.WithFields(
					log.Fields{
						"Family":   extracted.Config.Family,
						"Campaign": extracted.Config.Campaign,
					},
				).Infof("config info for %s", filePath)
			}

			for _, task := range report.Tasks {
				triageReport, err := client.SampleTaskReport(context.Background(), sample.ID, task.Name)
				if err != nil {
					log.WithFields(log.Fields{
						"error":   err,
						"profile": task.Name,
					}).Errorf("unable to get dynamic report")
					continue
				}

				for _, process := range triageReport.Processes {
					log.WithFields(log.Fields{
						"cmd":        process.Cmd,
						"pid":        process.PID,
						"parent pid": process.PPID,
						"image":      process.Image,
					}).Info("process info")
				}

				for _, netFlows := range triageReport.Network.Flows {
					if !whitelistedSites[netFlows.Domain] {
						log.WithFields(
							log.Fields{
								"profile": task.Name,
								"domain":  netFlows.Domain,
								"dest":    netFlows.Dest,
								"JA3":     netFlows.JA3,
								"JA3s":    netFlows.JA3S,
							}).Info("network connection")
					}
				}

				for _, dump := range triageReport.Dumped {
					log.WithFields(log.Fields{
						"dumped length": dump.Length,
						"pid":           dump.PID,
						"md5":           dump.MD5,
					}).Info("dump info")
				}
			}

		}
	},
}
