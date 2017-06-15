// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"database/sql"
	slib "github.com/mozilla/service-map/servicelib"
	"strings"
	"time"
)

// Given a host with a valid ID, populate the compliance status
// for the host.
func hostAddComp(op opContext, h *slib.Host) error {
	h.CompStatus.Reset()
	rows, err := op.Query(`SELECT checkref, status, timestamp
		FROM compscore x WHERE assetid = $1 AND
		timestamp > now() - interval '168 hours' AND
		timestamp = (
			SELECT MAX(timestamp) FROM compscore y
			WHERE assetid = $2 AND
			x.checkref = y.checkref AND
			timestamp > now() - interval '168 hours'
		)`, h.ID, h.ID)
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

	// Determine if we have coverage
	cutoff := time.Now().UTC().Add(-1 * time.Duration(time.Hour*72))
	rows, err := op.Query(`SELECT MAX(timestamp), checktype, status FROM
		vulnstatus WHERE assetid=$1 AND
		timestamp > $2 GROUP BY checktype, status`, h.ID, cutoff)
	if err != nil {
		return err
	}
	havecoverage := false
	for rows.Next() {
		var (
			t      time.Time
			check  string
			status bool
		)
		err = rows.Scan(&t, &check, &status)
		if err != nil {
			rows.Close()
			return err
		}
		if status {
			havecoverage = true
			rows.Close()
			break
		}
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	if havecoverage {
		h.VulnStatus.Coverage = true
	} else {
		h.VulnStatus.Coverage = false
		return nil
	}

	err = op.QueryRow(`SELECT maxcount, highcount,
		mediumcount, lowcount, likelihoodindicator, timestamp
		FROM vulnscore WHERE assetid = $1 AND
		timestamp > now() - interval '168 hours'
		ORDER BY timestamp DESC
		LIMIT 1`, h.ID).Scan(&h.VulnStatus.Maximum,
		&h.VulnStatus.High, &h.VulnStatus.Medium, &h.VulnStatus.Low,
		&h.VulnStatus.LikelihoodIndicator, &tstamp)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		} else {
			return err
		}
	}
	err = hostAddVulnLast90(op, h, tstamp)
	if err != nil {
		return err
	}
	return nil
}

// Add counts for a given host representing the number of days the host was
// known to have vulnerabilities of a given impact, within the last 90
// days but before tstamp
func hostAddVulnLast90(op opContext, h *slib.Host, tstamp time.Time) error {
	err := op.QueryRow(`WITH summary AS (
			SELECT date_trunc('day', timestamp) as day,
			sum(maxcount) as maxcount,
			sum(highcount) as highcount,
			sum(mediumcount) as mediumcount,
			sum(lowcount) as lowcount
			FROM vulnscore
			WHERE assetid = $1 AND
			timestamp > now() - interval '90 days' AND
			timestamp < $2
			GROUP BY day
		)
		SELECT
		sum(case when maxcount > 0 then 1 else 0 end) as maxdays,
		sum(case when highcount > 0 then 1 else 0 end) as highdays,
		sum(case when mediumcount > 0 then 1 else 0 end) as mediumdays,
		sum(case when lowcount > 0 then 1 else 0 end) as lowdays
		FROM summary`, h.ID, tstamp).Scan(&h.VulnStatus.Last90Days.DaysWithMaximum,
		&h.VulnStatus.Last90Days.DaysWithHigh,
		&h.VulnStatus.Last90Days.DaysWithMedium,
		&h.VulnStatus.Last90Days.DaysWithLow)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		} else {
			return err
		}
	}
	return nil
}
