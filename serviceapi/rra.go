// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	slib "github.com/mozilla/service-map/servicelib"
	"io/ioutil"
	"net/http"
	"strconv"
)

// Get a fully populated RRA by ID; if the event the requested ID does
// not exist, err will be nil and rr.Name will be the zero value
func getRRA(op opContext, rraid string) (rr slib.RRA, err error) {
	err = op.QueryRow(`SELECT rraid, service,
		impact_availrep, impact_availprd, impact_availfin,
		impact_confirep, impact_confiprd, impact_confifin,
		impact_integrep, impact_integprd, impact_integfin,
		prob_availrep, prob_availprd, prob_availfin,
		prob_confirep, prob_confiprd, prob_confifin,
		prob_integrep, prob_integprd, prob_integfin,
		datadefault, raw, lastupdated
		FROM rra WHERE rraid = $1`, rraid).Scan(&rr.ID, &rr.Name,
		&rr.AvailRepImpact, &rr.AvailPrdImpact, &rr.AvailFinImpact,
		&rr.ConfiRepImpact, &rr.ConfiPrdImpact, &rr.ConfiFinImpact,
		&rr.IntegRepImpact, &rr.IntegPrdImpact, &rr.IntegFinImpact,
		&rr.AvailRepProb, &rr.AvailPrdProb, &rr.AvailFinProb,
		&rr.ConfiRepProb, &rr.ConfiPrdProb, &rr.ConfiFinProb,
		&rr.IntegRepProb, &rr.IntegPrdProb, &rr.IntegFinProb,
		&rr.DefData, &rr.RawRRA, &rr.LastUpdated)
	if err != nil {
		if err == sql.ErrNoRows {
			return rr, nil
		} else {
			return
		}
	}
	err = rraResolveSupportGroups(op, &rr)
	if err != nil {
		return
	}
	return
}

func rraResolveSupportGroups(op opContext, r *slib.RRA) error {
	r.Groups = make([]slib.AssetGroup, 0)
	rows, err := op.Query(`SELECT assetgroupid FROM
		rra_assetgroup WHERE rraid = $1`,
		r.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var sgid int
		err = rows.Scan(&sgid)
		if err != nil {
			rows.Close()
			return err
		}
		sg, err := getAssetGroup(op, sgid)
		if err != nil {
			rows.Close()
			return err
		}
		if sg.Name == "" {
			continue
		}
		r.Groups = append(r.Groups, sg)
	}
	err = rows.Err()
	if err != nil {
		return err
	}
	return nil
}

// Return a risk document that includes all RRAs
func serviceRisks(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	rows, err := op.Query(`SELECT rraid FROM rra x
		WHERE lastmodified = (
			SELECT MAX(lastmodified) FROM rra y
			WHERE x.service = y.service
		)`)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	resp := slib.RisksResponse{}
	for rows.Next() {
		var rraid int
		err = rows.Scan(&rraid)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
		rs, err := riskForRRA(op, true, rraid)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
		resp.Risks = append(resp.Risks, rs)
	}
	err = rows.Err()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	buf, err := json.Marshal(&resp)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

// Calculate the risk for the requested RRA
func serviceGetRRARisk(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	rraid := req.FormValue("id")
	if rraid == "" {
		err := fmt.Errorf("no rra id specified")
		op.logf(err.Error())
		http.Error(rw, err.Error(), 400)
		return
	}
	r, err := strconv.Atoi(rraid)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	rs, err := riskForRRA(op, true, r)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	buf, err := json.Marshal(&rs)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

// Endpoint used to update RRAs in the database (RRA submission to serviceapi
// from rra2json.
func serviceUpdateRRA(rw http.ResponseWriter, req *http.Request) {
	var (
		buf    []byte
		err    error
		rawrra slib.RawRRA
	)
	buf, err = ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, err.Error(), 500)
	}

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	// First, unmarshal into a RawRRA and validate the incoming document
	err = json.Unmarshal(buf, &rawrra)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "rra document malformed", 400)
		return
	}
	err = rawrra.Validate()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "rra document malformed", 400)
		return
	}

	// Convert the incoming RRA into an RRA type, and insert it into the
	// database if required
	rra := rawrra.ToRRA()
	_, err = op.Exec(`INSERT INTO rra
		(service,
		impact_availrep, impact_availprd, impact_availfin,
		impact_confirep, impact_confiprd, impact_confifin,
		impact_integrep, impact_integprd, impact_integfin,
		prob_availrep, prob_availprd, prob_availfin,
		prob_confirep, prob_confiprd, prob_confifin,
		prob_integrep, prob_integprd, prob_integfin,
		datadefault, lastupdated, timestamp, raw)
		SELECT $1,
		$2, $3, $4,
		$5, $6, $7,
		$8, $9, $10,
		$11, $12, $13,
		$14, $15, $16,
		$17, $18, $19,
		$20, $21, now(), $22
		WHERE NOT EXISTS (
			SELECT 1 FROM rra WHERE service = $23 AND
			lastupdated = $24
		)`, rra.Name,
		rra.AvailRepImpact, rra.AvailPrdImpact, rra.AvailFinImpact,
		rra.ConfiRepImpact, rra.ConfiPrdImpact, rra.ConfiFinImpact,
		rra.IntegRepImpact, rra.IntegPrdImpact, rra.IntegFinImpact,
		rra.AvailRepProb, rra.AvailPrdProb, rra.AvailFinProb,
		rra.ConfiRepProb, rra.ConfiPrdProb, rra.ConfiFinProb,
		rra.IntegRepProb, rra.IntegPrdProb, rra.IntegFinProb,
		rra.DefData, rra.LastUpdated, buf,
		rra.Name, rra.LastUpdated)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error processing rra", 500)
		return
	}
}

// API entry point to retrieve a specific RRA. All details including the
// original RRA document are returned.
func serviceGetRRA(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	rraid := req.FormValue("id")
	if rraid == "" {
		err := fmt.Errorf("no rra id specified")
		op.logf(err.Error())
		http.Error(rw, err.Error(), 400)
		return
	}

	r, err := getRRA(op, rraid)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving rra", 500)
		return
	}

	buf, err := json.Marshal(&r)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving rra", 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

// API entry point to retrieve a list of all RRAs. The response is a slice of
// RRA types (RRAsResponse), note though we only populate a few elements inside
// the RRA
func serviceRRAs(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	rows, err := op.Query(`SELECT rraid, service, lastupdated, datadefault
		FROM rra x WHERE lastupdated = (
			SELECT MAX(lastupdated) FROM rra y WHERE
			x.service = y.service
		)`)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving rra list", 500)
		return
	}
	srr := slib.RRAsResponse{}
	srr.RRAs = make([]slib.RRA, 0)
	for rows.Next() {
		var s slib.RRA
		err = rows.Scan(&s.ID, &s.Name, &s.LastUpdated, &s.DefData)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, "error retrieving rra list", 500)
			return
		}
		srr.RRAs = append(srr.RRAs, s)
	}
	err = rows.Err()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving rra list", 500)
		return
	}

	buf, err := json.Marshal(&srr)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving rra list", 500)
		return
	}
	fmt.Fprint(rw, string(buf))
}