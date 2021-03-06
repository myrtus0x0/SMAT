package cmd

import (
	"context"
	"io/ioutil"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/vertoforce/gourlhaus"
)

func init() {
	urlhausCmd.AddCommand(urlhausCheckCmd)
}

var urlhausCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "checks if a url or set of urls exists within urlhaus",
	Long: `When dealing with incidents that require sensitvity, this command allows you to check if a URL already exists in urlhaus but will not upload it to the dataset.
Can be beneficial for initial investigations.
Format:
	
	smat urlhaus check more_files_with_urls..

Example usage:

	smat urlhaus check /tmp/buer.txt 
	smat urlhaus check /tmp/buer.txt /tmp/qakbot.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		for _, filename := range args {
			fileContents, err := ioutil.ReadFile(filename)
			if err != nil {
				log.Warnf("unable to read file: %s", err)
				continue
			}

			urls := strings.Split(string(fileContents), "\n")
			cleanedURLS := []string{}
			for _, url := range urls {
				if url != "" {
					cleanedURLS = append(cleanedURLS, url)
				}
			}
			entries, err := gourlhaus.CheckForUnseenURLs(ctx, cleanedURLS)
			if err != nil {
				log.Warnf("unable to find sample: %s", err)
				continue
			}

			if len(entries) == 0 {
				log.Info("All URLs have been submitted already!")
			} else {
				for _, entry := range entries {
					log.Infof("URL Doesnt exist: %s", entry)
				}
			}
		}
	},
}
