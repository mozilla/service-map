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
)

var esRequestMax = 1000000

func requestComplianceHosts() ([]string, error) {
	type fieldResponse struct {
		Hostname []string `json:"target"`
	}
	var ret []string

	conn := elastigo.NewConn()
	defer conn.Close()
	conn.Domain = cfg.Compliance.ESHost

	template := `{
		"size": %v,
		"fields": [ "target" ],
		"query": {
			"bool": {
				"must": [
				{
					"term": {
						"_type": "last_known_state"
					}
				},
				{
					"range": {
						"utctimestamp": {
							"gt": "now-7d"
						}
					}
				}
				]
			}
		}
	}`
	tempbuf := fmt.Sprintf(template, esRequestMax)
	res, err := conn.Search(cfg.Compliance.Index, "last_known_state", nil, tempbuf)
	if err != nil {
		return ret, err
	}
	for _, x := range res.Hits.Hits {
		var nfr fieldResponse
		err = json.Unmarshal(*x.Fields, &nfr)
		if err != nil {
			return ret, err
		}
		if len(nfr.Hostname) == 0 {
			continue
		}
		found := false
		for _, y := range ret {
			if y == nfr.Hostname[0] {
				found = true
				break
			}
		}
		if found {
			continue
		}
		ret = append(ret, nfr.Hostname[0])
	}
	logf("importcomphosts: fetched %v candidates", len(ret))

	return ret, nil
}

func dbUpdateCompHost(hn string) error {
	op := opContext{}
	op.newContext(dbconn, false, "importcomphosts")
	return updateDynamicHost(op, hn, "compliance importer")
}

func importCompHosts() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in compliance host import routine: %v", e)
		}
	}()
	hosts, err := requestComplianceHosts()
	if err != nil {
		panic(err)
	}
	for _, x := range hosts {
		err = dbUpdateCompHost(x)
		if err != nil {
			panic(err)
		}
	}
}
