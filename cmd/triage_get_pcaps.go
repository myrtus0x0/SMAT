package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	triage "github.com/hatching/triage/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var client *triage.Client

func init() {
	triageCmd.AddCommand(getPcapsCmd)
}

var getPcapsCmd = &cobra.Command{
	Use:   "get_pcaps",
	Short: "returns all pcap ng files for a specific family",
	Long:  `returns all pcap ng files for a specific family`,
	Run: func(cmd *cobra.Command, args []string) {
		client := triage.NewClientWithRootURL(os.Getenv("TRIAGE_KEY"), triageAPI)
		for _, family := range args {
			sampleChan := client.Search(context.Background(), fmt.Sprintf("family:%s", family), 500)
			for sample := range sampleChan {
				for _, task := range sample.Tasks {
					log.Infof("pulling task %s for sample %s", task.ID, sample.Filename)
					report, err := client.SampleTaskReport(context.Background(), sample.ID, task.ID)
					if err != nil {
						log.Errorf("unable to fetch report for %s", sample.ID)
						continue
					}

					log.Info(report.Version)

					apiEndpoint := fmt.Sprintf(triageAPI+"/v0/samples/%s/%s/dump.pcapng", sample.ID, task.ID)
					body := bytes.NewBuffer([]byte{})
					req, err := http.NewRequest(http.MethodGet, apiEndpoint, body)
					if err != nil {
						log.Error("unable to initialize request")
						continue
					}

					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", os.Getenv("TRIAGE_KEY")))

					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						log.Error("unable to make GET request tp PCAP")
						continue
					}

					contents, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						log.Errorf("unable to read resp")
						continue
					} else if len(contents) == 0 {
						log.Error("no data received for PCAP")
						continue
					}

					filename := sample.ID + "_" + task.ID + "_" + "dump.pcapng"
					log.Infof("writing pcap to %s", filename)
					log.Infof("length of pcap: %d", len(contents))
					ioutil.WriteFile(filename, contents, 0644)
				}
			}
		}
	},
}
