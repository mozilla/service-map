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
	"strings"
	"time"
)

// Query the database for a list of hosts we need to update vulnerability
// scores for; we want to return at most the batch size specified in the
// configuration file
func scoreVulnGetHosts() (ret map[int]string, err error) {
	ret = make(map[int]string)
	// Just use the API opContext to access the database
	op := opContext{}
	op.newContext(dbconn, false, "scorevuln")

	dur, err := time.ParseDuration(cfg.Vulnerabilities.ScoreEvery)
	if err != nil {
		return
	}
	cutoff := time.Now().UTC().Add(-1 * dur)

	// Grab a list of candidate hosts
	rows, err := op.Query(`SELECT assetid, hostname FROM asset
		WHERE lastvulnscore < $1 AND assettype = 'host'
		ORDER BY lastvulnscore LIMIT $2`, cutoff, cfg.Vulnerabilities.ScoringBatchSize)
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

// Request vulnerability for hostname h from ES and update the vuln
// scoring table with the result
func scoreVulnScoreHost(hid int, h string) (err error) {
	conn := elastigo.NewConn()
	defer conn.Close()
	conn.Domain = cfg.Compliance.ESHost

	op := opContext{}
	op.newContext(dbconn, false, "scorevuln")

	defer func() {
		_, e := op.Exec(`UPDATE asset SET
		lastvulnscore = now()
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

	logf("scorevuln: processing %v", h)
	template := `{
		"size": 1000000,
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
	tempbuf := fmt.Sprintf(template, h)
	res, err := conn.Search(cfg.Vulnerabilities.Index, "vulnerability_state", nil, tempbuf)
	if err != nil {
		return err
	}

	var maxcnt, highcnt, medcnt, lowcnt int
	var vi []gozdef.VulnEvent

	highlike := 1

	if res.Hits.Len() == 0 {
		// If we didn't get any results, it could be because the host is not being
		// assessed, or there are no known issues. We want to insert an entry indicating
		// no issues. This should not provide invalid information for hosts that are
		// not assessed, as vulnstatus should note the status of coverage for the host
		// when we perform risk calculation.
		goto skipanalyze
	}
	for _, x := range res.Hits.Hits {
		var nvi gozdef.VulnEvent
		err = json.Unmarshal(*x.Source, &nvi)
		vi = append(vi, nvi)
	}

	// Count issues on the host
	for _, x := range vi {
		var tl int
		// We want the highest likelihood indicator value from the set
		if x.Vuln.LikelihoodIndicator != "" {
			switch strings.ToLower(x.Vuln.LikelihoodIndicator) {
			case "maximum":
				tl = 4
			case "high":
				tl = 3
			case "medium":
				tl = 2
			case "low":
				tl = 1
			default:
				logf("warning: vulnscore: entry for %v (%v) has invalid likelihood indicator",
					h, x.Vuln.VulnID)
			}
		}
		if tl > highlike {
			highlike = tl
		}
		// First try the impact label, if that is not successful try the CVSS score
		if x.Vuln.ImpactLabel != "" {
			switch strings.ToLower(x.Vuln.ImpactLabel) {
			case "maximum":
				maxcnt++
			case "high":
				highcnt++
			case "mediumlow":
				medcnt++
			case "medium":
				medcnt++
			case "low":
				lowcnt++
			default:
				logf("warning: vulnscore: entry for %v (%v) has invalid impact label",
					h, x.Vuln.VulnID)
			}
		} else if x.Vuln.CVSS > 0 {
			if x.Vuln.CVSS > 9.0 {
				maxcnt++
			} else if x.Vuln.CVSS > 7.0 {
				highcnt++
			} else if x.Vuln.CVSS > 5.0 {
				medcnt++
			} else {
				lowcnt++
			}
		} else {
			logf("warning: vulnscore: entry for %v (%v) has no usable information",
				h, x.Vuln.VulnID)
		}
	}

skipanalyze:
	_, err = op.Exec(`INSERT INTO vulnscore
		(timestamp, assetid, maxcount, highcount, mediumcount, lowcount,
		likelihoodindicator)
		VALUES
		(now(),
		(SELECT assetid FROM asset
		WHERE lower(hostname) = lower($1)
		AND assettype = 'host'
		AND assetid = $2),
		$3, $4, $5, $6, $7)`, h, hid, maxcnt, highcnt, medcnt, lowcnt, highlike)
	if err != nil {
		return err
	}

	return nil
}

// Entry point for compliance scoring routine
func scoreVuln() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in vulnerability scoring routine: %v", e)
		}
	}()
	hl, err := scoreVulnGetHosts()
	if err != nil {
		panic(err)
	}
	for hid, hname := range hl {
		err = scoreVulnScoreHost(hid, hname)
		if err != nil {
			panic(err)
		}
	}
}
