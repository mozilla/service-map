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
	"github.com/jvehent/gozdef"
	elastigo "github.com/mattbaird/elastigo/lib"
	"net/http"
	slib "servicelib"
)

func getTargetVulns(target string) ([]gozdef.VulnEvent, error) {
	ret := make([]gozdef.VulnEvent, 0)

	conn := elastigo.NewConn()
	conn.Domain = cfg.Vulnerabilities.ESHost

	template := `{
		"from": %v,
		"size": 10,
		"sort": [
		{ "_id": "asc" }
		],
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
						"status": "open"
					}
				},
				{
					"term": {
						"sourcename": "production"
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
	for i := 0; ; i += 10 {
		tempbuf := fmt.Sprintf(template, i, target)
		res, err := conn.Search(cfg.Vulnerabilities.Index, "vulnerability_state",
			nil, tempbuf)
		if err != nil {
			return ret, err
		}
		if res.Hits.Len() == 0 {
			break
		}
		for _, x := range res.Hits.Hits {
			var nv gozdef.VulnEvent
			err = json.Unmarshal(*x.Source, &nv)
			if err != nil {
				return ret, err
			}
			ret = append(ret, nv)
		}
	}

	return ret, nil
}

func serviceGetVulnsTarget(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	target := req.FormValue("target")
	if target == "" {
		http.Error(rw, "must specify target for query", 500)
		return
	}

	vl, err := getTargetVulns(target)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	resp := slib.VulnsTargetResponse{}
	resp.Vulnerabilities = vl

	buf, err := json.Marshal(&resp)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}
