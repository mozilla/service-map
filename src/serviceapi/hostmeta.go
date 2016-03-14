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
	"strings"
	"time"
)

// Given a host with a valid ID, populate the compliance status
// for the host.
func hostAddComp(op opContext, h *slib.Host) error {
	h.CompStatus.Reset()
	rows, err := op.Query(`SELECT checkref, status,
		MAX(timestamp) FROM compscore WHERE hostid = $1 AND
		timestamp > now() AT TIME ZONE 'utc' -
		interval '168 hours' GROUP BY checkref, status`, h.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var sts bool
		var refname string
		var tstamp time.Time
		err = rows.Scan(&refname, &sts, &tstamp)
		if err != nil {
			rows.Close()
			return err
		}
		// XXX Determine the class based on a substring match in the
		// check reference name, it would be better to store the
		// compliance check level itself from the compliance item
		// (policy.level).
		if strings.Contains(refname, "low") {
			if sts {
				h.CompStatus.LowPass++
			} else {
				h.CompStatus.LowFail++
			}
		} else if strings.Contains(refname, "medium") {
			if sts {
				h.CompStatus.MediumPass++
			} else {
				h.CompStatus.MediumFail++
			}
		} else if strings.Contains(refname, "high") {
			if sts {
				h.CompStatus.HighPass++
			} else {
				h.CompStatus.HighFail++
			}
		}

		// Add a details entry for the item
		ncd := slib.ComplianceDetails{}
		ncd.CheckRef = refname
		ncd.Status = sts
		ncd.Timestamp = tstamp
		h.CompStatus.Details = append(h.CompStatus.Details, ncd)
	}
	return nil
}

// Given a host with a valid ID, populate the vulnerability status
// for the host.
func hostAddVuln(op opContext, h *slib.Host) error {
	var tstamp time.Time
	h.VulnStatus.Reset()
	err := op.QueryRow(`SELECT maxcount, highcount,
		mediumcount, lowcount, MAX(timestamp)
		FROM vulnscore WHERE hostid = $1 AND
		timestamp > now() AT TIME ZONE 'utc' -
		interval '168 hours'
		GROUP BY maxcount, highcount,
		mediumcount, lowcount`, h.ID).Scan(&h.VulnStatus.Maximum,
		&h.VulnStatus.High, &h.VulnStatus.Medium, &h.VulnStatus.Low, &tstamp)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		} else {
			return err
		}
	}
	return nil
}
