// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"github.com/ameihm0912/http-observatory-go"
	"time"
)

// Query the database for a list of hosts we need to update observatory
// scores for; we want to return at most the batch size specified in the
// configuration file
func scoreHTTPObsGetHosts() (ret map[int]string, err error) {
	ret = make(map[int]string)
	// Just use the API opContext to access the database
	op := opContext{}
	op.newContext(dbconn, false, "scorehttpobs")

	dur, err := time.ParseDuration(cfg.HTTPObs.ScoreEvery)
	if err != nil {
		return
	}
	cutoff := time.Now().UTC().Add(-1 * dur)

	// Grab a list of candidate hosts
	rows, err := op.Query(`SELECT assetid, website FROM asset
		WHERE lasthttpobsscore < $1 AND assettype = 'website'
		ORDER BY lasthttpobsscore LIMIT $2`, cutoff, cfg.HTTPObs.ScoringBatchSize)
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

// Request score for website w from httpobs and update the
// scoring table with the result
func scoreHTTPObsSite(wid int, w string) (err error) {
	op := opContext{}
	op.newContext(dbconn, false, "scorehttpobs")

	defer func() {
		_, e := op.Exec(`UPDATE asset SET
		lasthttpobsscore = now() AT TIME ZONE 'utc'
		WHERE lower(website) = lower($1)
		AND assettype = 'website'
		AND assetid = $2`, w, wid)
		if e != nil {
			// Only change the error message if we haven't already
			// encountered an error
			if err != nil {
				err = e
			}
		}
	}()

	logf("scorehttpobs: processing %v", w)
	results, err := httpobsgo.RunScan(w, false, false)
	if err != nil {
		return err
	}
	_, err = op.Exec(`INSERT INTO httpobsscore
			(timestamp, assetid, score, grade,
			passcount, failcount, totalcount)
			VALUES
			(now() AT TIME ZONE 'utc',
			(SELECT assetid FROM asset
			WHERE lower(website) = lower($1)
			AND assettype = 'website'
			AND assetid = $2),
			$3, $4, $5, $6, $7)`,
		w, wid, results.Score, results.Grade,
		results.TestsPassed, results.TestsFailed, results.TestsQuantity)
	if err != nil {
		return err
	}

	return nil
}

// Entry point for HTTP observatory scoring routine
func scoreHTTPObs() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in http observatory scoring routine: %v", e)
		}
	}()
	wl, err := scoreHTTPObsGetHosts()
	if err != nil {
		panic(err)
	}
	for wid, website := range wl {
		err = scoreHTTPObsSite(wid, website)
		if err != nil {
			panic(err)
		}
	}
}
