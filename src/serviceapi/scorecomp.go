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
	"github.com/ameihm0912/gozdef"
	elastigo "github.com/mattbaird/elastigo/lib"
	"time"
)

// Query the database for a list of hosts we need to update compliance
// scores for; we want to return at most the batch size specified in the
// configuration file
func scoreComplianceGetHosts() (ret map[int]string, err error) {
	ret = make(map[int]string)
	// Just use the API opContext to access the database
	op := opContext{}
	op.newContext(dbconn, false, "scorecomp")

	dur, err := time.ParseDuration(cfg.Compliance.ScoreEvery)
	if err != nil {
		return
	}
	cutoff := time.Now().UTC().Add(-1 * dur)

	// Grab a list of candidate hosts
	rows, err := op.Query(`SELECT assetid, hostname FROM asset
		WHERE lastcompscore < $1 AND assettype = 'host'
		ORDER BY lastcompscore LIMIT $2`, cutoff, cfg.Compliance.ScoringBatchSize)
	if err != nil {
		return
	}
	for rows.Next() {
		var (
			h   string
			hid int
		)
		err = rows.Scan(&hid, &h)
		if err != nil {
			return
		}
		ret[hid] = h
	}

	return
}

// Request compliance items for hostname h from ES and update the compliance
// scoring table with the result
func scoreComplianceScoreHost(hid int, h string) (err error) {
	conn := elastigo.NewConn()
	defer conn.Close()
	conn.Domain = cfg.Compliance.ESHost

	op := opContext{}
	op.newContext(dbconn, false, "scorecomp")

	defer func() {
		_, e := op.Exec(`UPDATE asset SET
		lastcompscore = now()
		WHERE lower(hostname) = lower($1)
		AND assettype = 'host'
		AND assetid = $2`, h, hid)
		if e != nil {
			// Only change the error message if we haven't already
			// encountered an error
			if err != nil {
				err = e
			}
		}
	}()

	logf("scorecomp: processing %v", h)
	template := `{
		"size": 1000000,
		"query": {
			"bool": {
				"must": [
				{
					"term": {
						"_type": "last_known_state"
					}
				},
				{
					"query_string": {
						"query": "target: \"%v\""
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
	tempbuf := fmt.Sprintf(template, h)
	res, err := conn.Search(cfg.Compliance.Index, "last_known_state", nil, tempbuf)
	if err != nil {
		return err
	}
	if res.Hits.Len() == 0 {
		return nil
	}
	var ci []gozdef.ComplianceItem
	for _, x := range res.Hits.Hits {
		var nci gozdef.ComplianceItem
		err = json.Unmarshal(*x.Source, &nci)
		ci = append(ci, nci)
	}

	statusmap := make(map[string]bool)
	for _, x := range ci {
		if x.Compliance {
			statusmap[x.Check.Ref] = true
		} else {
			statusmap[x.Check.Ref] = false
		}
	}

	// Insert the items into the compliance score table
	for x := range statusmap {
		iname := x
		ivalue := statusmap[x]
		_, err = op.Exec(`INSERT INTO compscore
			(timestamp, assetid, checkref, status)
			VALUES
			(now(),
			(SELECT assetid FROM asset
			WHERE lower(hostname) = lower($1)
			AND assettype = 'host'
			AND assetid = $2),
			$3, $4)`, h, hid, iname, ivalue)
		if err != nil {
			return err
		}
	}

	return nil
}

// Entry point for compliance scoring routine
func scoreCompliance() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in compliance scoring routine: %v", e)
		}
	}()
	hl, err := scoreComplianceGetHosts()
	if err != nil {
		panic(err)
	}
	for hid, hname := range hl {
		err = scoreComplianceScoreHost(hid, hname)
		if err != nil {
			panic(err)
		}
	}
}
