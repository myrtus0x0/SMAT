package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"

	triage "github.com/hatching/triage/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	triageCmd.AddCommand(getJA3Cmd)
}

type ja3Result struct {
	domain string
	ja3    string
	ja3s   string
	srcIP  string
	dstIP  string
}

func rankByCount(ja3Frequencies map[string]int) pairList {
	pl := make(pairList, len(ja3Frequencies))
	i := 0
	for k, v := range ja3Frequencies {
		pl[i] = pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(pl))
	return pl
}

type pair struct {
	Key   string
	Value int
}

type pairList []pair

func (p pairList) Len() int           { return len(p) }
func (p pairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p pairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

var getJA3Cmd = &cobra.Command{
	Use:   "get_JA3s",
	Short: "returns all ja3 and ja3s signatures for specific malware family",
	Long:  `returns all ja3 and ja3s signatures for specific malware family`,
	Run: func(cmd *cobra.Command, args []string) {
		seenJAs := map[string]ja3Result{}
		totalJAs := map[string]int{}
		totalJA3s := map[string]int{}
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
					for _, flow := range report.Network.Flows {
						if flow.Domain != "" && flow.JA3 != "" && flow.JA3S != "" {
							res := &ja3Result{}

							res.domain = flow.Domain
							res.ja3 = flow.JA3
							res.ja3s = flow.JA3S
							res.dstIP = flow.Dest
							res.srcIP = flow.Source

							seenJAs[res.domain] = *res
						}
					}
				}
			}
			for _, result := range seenJAs {
				log.WithFields(log.Fields{
					"JA3":    result.ja3,
					"JA3s":   result.ja3s,
					"Domain": result.domain,
					"Src IP": result.srcIP,
					"Dst IP": result.dstIP,
					"Family": family,
				}).Info("Flow data")

				totalJAs[result.ja3]++
				totalJA3s[result.ja3s]++
			}

			sortedJA3s := rankByCount(totalJA3s)
			sortedJAs := rankByCount(totalJAs)

			for _, ja3 := range sortedJAs {
				log.WithFields(log.Fields{
					"JA3":   ja3.Key,
					"Count": ja3.Value,
				}).Info("JA3 occurances")
			}

			for _, ja3 := range sortedJA3s {
				log.WithFields(log.Fields{
					"JA3s":  ja3.Key,
					"Count": ja3.Value,
				}).Info("JA3s occurances")
			}
		}
	},
}
