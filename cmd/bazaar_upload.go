package cmd

import (
	"context"
	"io/ioutil"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/vertoforce/go-malwarebazaar"
)

var bazaarTags string
var deliveryMethod string

func init() {
	bazaarCmd.AddCommand(UploadCmd)
	bazaarCmd.PersistentFlags().StringVarP(&bazaarTags, "tags", "t", "", "comma split list of tags to apply")
	bazaarCmd.PersistentFlags().StringVarP(&deliveryMethod, "method", "n", "", "oen of: email_attachment, email_link, web_download, web_drive-by, multiple")

}

var UploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "uploads a sample or samples to malware bazaar",
	Long:  `uploads a sample or samples to malware bazaar. This call requires an API key and will be read from an env variable with the name BAZA_KEY`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		tags := strings.Split(bazaarTags, ",")

		for _, file := range args {
			contents, err := ioutil.ReadFile(file)
			if err != nil {
				log.Fatal(err)
			}

			resp, err := malwarebazaar.UploadFile(ctx, "", contents, false, tags, deliveryMethod, os.Getenv("BAZA_KEY"))
			if err != nil {
				log.Fatal(err)
			}

			log.Info(resp)
		}
	},
}
