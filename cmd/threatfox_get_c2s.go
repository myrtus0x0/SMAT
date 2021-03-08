package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	foxCmd.AddCommand(getC2s)
}

const (
	threatFoxAPI = "https://threatfox-api.abuse.ch/api/v1/"
)

type getC2SReq struct {
	Query string `json:"query"`
	Days  int    `json:"days"`
}

type getC2SResp struct {
	QueryStatus string  `json:"query_status"`
	Data        []c2Obj `json:"data"`
}

type c2Obj struct {
	ID               string      `json:"id"`
	Ioc              string      `json:"ioc"`
	ThreatType       string      `json:"threat_type"`
	ThreatTypeDesc   string      `json:"threat_type_desc"`
	IocType          string      `json:"ioc_type"`
	IocTypeDesc      string      `json:"ioc_type_desc"`
	Malware          string      `json:"malware"`
	MalwarePrintable string      `json:"malware_printable"`
	MalwareAlias     interface{} `json:"malware_alias"`
	MalwareMalpedia  string      `json:"malware_malpedia"`
	ConfidenceLevel  int64       `json:"confidence_level"`
	FirstSeen        string      `json:"first_seen"`
	LastSeen         interface{} `json:"last_seen"`
	Reporter         string      `json:"reporter"`
	Reference        *string     `json:"reference"`
	Tags             []string    `json:"tags"`
}

var getC2s = &cobra.Command{
	Use:   "get_c2s",
	Short: "returns all C2s held in the ThreatFox C2 repository",
	Long:  `returns all C2s held in the ThreatFox C2 repository`,
	Run: func(cmd *cobra.Command, args []string) {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		req := &getC2SReq{
			Query: "get_iocs",
			Days:  7,
		}

		marshalledReq, err := json.Marshal(req)
		if err != nil {
			log.Fatal(err)
		}

		resp, err := http.Post(threatFoxAPI, "", bytes.NewBuffer(marshalledReq))
		if err != nil {
			log.Fatal(err)
		}

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		unmarshalledResp := &getC2SResp{}
		err = json.Unmarshal(contents, unmarshalledResp)
		if err != nil {
			log.Fatal(err)
		}

		for _, c2 := range unmarshalledResp.Data {
			log.WithFields(log.Fields{
				"family": c2.Malware,
				"C2":     c2.Ioc,
				"tags":   c2.Tags,
			}).Info("C2 info")
		}
	},
}
