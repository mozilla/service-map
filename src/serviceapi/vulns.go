// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"
	"fmt"
	elastigo "github.com/mattbaird/elastigo/lib"
	"net/http"
	slib "servicelib"
)

func getTargetVulns(target string) (ret slib.Vuln, err error) {
	conn := elastigo.NewConn()
	defer conn.Close()
	conn.Domain = cfg.Vulnerabilities.ESHost

	// We'll expect one document for the host, but query for more so we can
	// potentially generate a notice if duplicate documents for the same host
	// are in the index.
	template := `{
		"size": 10,
		"query": {
			"bool": {
				"must": [
				{
					"query_string": {
						"query": "asset.hostname: \"%v\""
					}
				},
				{
					"term": {
						"sourcename": "scanapi"
					}
				},
				{
					"range": {
						"utctimestamp": {
							"gt": "now-2d"
						}
					}
				}
				]
			}
		}
	}`
	tempbuf := fmt.Sprintf(template, target)
	res, err := conn.Search(cfg.Vulnerabilities.Index, "vulnerability_state",
		nil, tempbuf)
	if err != nil {
		return ret, err
	}
	if res.Hits.Len() == 0 {
		return ret, nil
	}
	err = json.Unmarshal(*res.Hits.Hits[0].Source, &ret)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func serviceGetVulnsTarget(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	target := req.FormValue("target")
	if target == "" {
		logf("must specify target for query")
		http.Error(rw, "must specify target for query", 500)
		return
	}

	vl, err := getTargetVulns(target)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	resp := slib.VulnsTargetResponse{}
	resp.Vulnerabilities = vl

	buf, err := json.Marshal(&resp)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}
