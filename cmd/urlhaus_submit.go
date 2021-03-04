package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/vertoforce/gourlhaus"
)

var (
	csvTags = ""
	threat  = "malware_download"
)

func init() {
	urlhausCmd.AddCommand(urlhausSubmitCmd)
	urlhausSubmitCmd.PersistentFlags().StringVarP(&csvTags, "tags", "t", "", "tags for the sample")
}

var urlhausSubmitCmd = &cobra.Command{
	Use:   "submit",
	Short: "uploads the list of URLs to urlhaus",
	Long: `submit takes in a list of filenames and will read each line in the file and attempt to submit the URLs to urlhaus. 
The tags passed are going to be applied to each URL across all files, so best to upload similarly categorized URLs together.
Format:
	
	smat urlhaus submit more_files_with_urls.. [--tag]

Example usage:

	smat urlhaus submit /tmp/buer.txt --tags buer
	smat urlhaus submit /tmp/buer.txt /tmp/qakbot.txt --tags malware
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if csvTags == "" {
			log.Fatal("tags are required")
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		for _, filename := range args {
			fileContents, err := ioutil.ReadFile(filename)
			if err != nil {
				log.Warnf("unable to read file: %s", err)
				continue
			}
			apiKey := os.Getenv("URLHAUS")
			tags := strings.Split(csvTags, ",")
			urls := strings.Split(string(fileContents), "\n")
			entries, err := gourlhaus.SubmitURLs(ctx, urls, apiKey, tags, threat)
			if err != nil {
				log.Warnf("unable submit samples: %s", err)
				continue
			}

			content, err := ioutil.ReadAll(entries)
			if err != nil {
				log.Fatal("unable to read response")
			}

			fmt.Printf("%s\n", content)
		}

	},
}
