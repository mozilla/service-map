// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"database/sql"
	slib "servicelib"
	"time"
)

// Add metadata for a web-site related to HTTP observatory output
func siteAddHTTPObs(op opContext, w *slib.Website) error {
	var tstamp time.Time

	w.HTTPObs.Coverage = false
	err := op.QueryRow(`SELECT score, grade,
		passcount, failcount, totalcount,
		MAX(timestamp)
		FROM httpobsscore WHERE assetid = $1 AND
		timestamp > now() -
		interval '168 hours'
		GROUP BY score, grade,
		passcount, failcount, totalcount`, w.ID).Scan(&w.HTTPObs.Score,
		&w.HTTPObs.Grade, &w.HTTPObs.TestsPassed, &w.HTTPObs.TestsFailed,
		&w.HTTPObs.TestsTotal, &tstamp)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		} else {
			return err
		}
	}
	w.HTTPObs.Coverage = true
	return nil
}
