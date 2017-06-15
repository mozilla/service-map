// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"mig.ninja/mig"
	"mig.ninja/mig/client"
	"net/http"
	"net/url"
	"os"
	"path"
	slib "servicelib"
)

// Small program to extract MIG agent information from the API and push
// the details into serviceapi as an indicator

const agentTarget = "status='online'"

var postOut string
var noVerify bool

func agentToIndicator(a mig.Agent) (ret slib.Indicator, err error) {
	ret.Host = a.Name
	ret.Class = "mig"
	ret.MIG.MIGHostname = a.Name
	ret.MIG.MIGVersion = a.Version
	ret.MIG.Tags = a.Tags
	ret.MIG.Environment = a.Env
	return
}

func sendIndicators(indparam slib.IndicatorParams) error {
	if postOut == "-" {
		for _, x := range indparam.Indicators {
			buf, err := json.Marshal(&x)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error marshaling indicator: %v\n", err)
				continue
			}
			fmt.Printf("%v\n", string(buf))
		}
		return nil
	}
	buf, err := json.Marshal(&indparam)
	if err != nil {
		return err
	}
	tcfg := &http.Transport{}
	if noVerify {
		tcfg.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	clnt := http.Client{Transport: tcfg}
	form := url.Values{}
	form.Add("params", string(buf))
	resp, err := clnt.PostForm(postOut, form)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("request failed: %v", resp.Status)
	}
	return nil
}

func main() {
	var cconf client.Configuration

	if len(os.Args) != 2 {
		fmt.Printf("usage: %v [- | indicator_post_url]\n", os.Args[0])
		os.Exit(1)
	}
	postOut = os.Args[1]

	dbg := os.Getenv("DEBUG")
	if dbg != "" {
		noVerify = true
	}

	confpath := path.Join(client.FindHomedir(), ".migrc")
	cconf, err := client.ReadConfiguration(confpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	cconf, err = client.ReadEnvConfiguration(cconf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cli, err := client.NewClient(cconf, "migindicators")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	agents, err := cli.EvaluateAgentTarget(agentTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	var indparam slib.IndicatorParams
	for _, agt := range agents {
		ind, err := agentToIndicator(agt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error converting agent to indicator: %v", err)
			continue
		}
		indparam.Indicators = append(indparam.Indicators, ind)
	}
	err = sendIndicators(indparam)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
