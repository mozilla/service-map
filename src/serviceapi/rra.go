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
	"net/http"
	slib "servicelib"
	"strconv"
)

func getRRA(op opContext, rraid string) (slib.RRAService, error) {
	var rr slib.RRAService

	err := op.QueryRow(`SELECT rraid, service,
		ari, api, afi, cri, cpi, cfi,
		iri, ipi, ifi,
		arp, app, afp, crp, cpp, cfp,
		irp, ipp, ifp, datadefault, raw
		FROM rra WHERE rraid = $1`, rraid).Scan(&rr.ID,
		&rr.Name, &rr.AvailRepImpact, &rr.AvailPrdImpact,
		&rr.AvailFinImpact, &rr.ConfiRepImpact, &rr.ConfiPrdImpact, &rr.ConfiFinImpact,
		&rr.IntegRepImpact, &rr.IntegPrdImpact, &rr.IntegFinImpact,
		&rr.AvailRepProb, &rr.AvailPrdProb, &rr.AvailFinProb,
		&rr.ConfiRepProb, &rr.ConfiPrdProb, &rr.ConfiFinProb,
		&rr.IntegRepProb, &rr.IntegPrdProb, &rr.IntegFinProb,
		&rr.DefData, &rr.RawRRA)
	if err != nil {
		if err == sql.ErrNoRows {
			return rr, nil
		} else {
			return rr, err
		}
	}
	err = rraResolveSupportGroups(op, &rr)
	if err != nil {
		return rr, err
	}

	return rr, nil
}

func rraResolveSupportGroups(op opContext, r *slib.RRAService) error {
	r.SupportGrps = make([]slib.SystemGroup, 0)
	rows, err := op.Query(`SELECT sysgroupid FROM
		rra_sysgroup WHERE rraid = $1`,
		r.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var sgid string
		err = rows.Scan(&sgid)
		if err != nil {
			rows.Close()
			return err
		}
		sg, err := getSysGroup(op, sgid)
		if err != nil {
			rows.Close()
			return err
		}
		if sg.Name == "" {
			continue
		}
		r.SupportGrps = append(r.SupportGrps, sg)
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

	rows, err := op.Query(`SELECT rraid FROM rra`)
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

// Read incoming RRA and update database as required. This can result in a
// new RRA being added, or an existing RRA being updated.
func serviceUpdateRRA(rw http.ResponseWriter, req *http.Request) {
	req.ParseMultipartForm(10000000)

	rawrra := req.FormValue("rra")
	if rawrra == "" {
		logf("no rra parameter in update request")
		http.Error(rw, "no rra parameter in update request", 500)
		return
	}

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	// XXX Use the same import function we use in the RRA importer for now.
	// This can be cleaned up once the RRA importer is removed and the POST
	// functionality for RRAs is being used exclusively.
	var (
		nrra    rraESData
		rraList []rraESData
	)
	err := json.Unmarshal([]byte(rawrra), &nrra.rra)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	err = json.Unmarshal([]byte(rawrra), &nrra.raw)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	err = nrra.rra.validate()
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	rraList = append(rraList, nrra)

	err = dbUpdateRRAs(rraList)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	ur := slib.RRAUpdateResponse{OK: true}
	buf, err := json.Marshal(&ur)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

// API entry point to retrieve specific RRA details
func serviceGetRRA(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	rraid := req.FormValue("id")

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	r, err := getRRA(op, rraid)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	buf, err := json.Marshal(&r)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

// API entry point to retrieve all RRAs
func serviceRRAs(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	rows, err := op.Query(`SELECT rraid, service, datadefault
		FROM rra x WHERE lastmodified = (
			SELECT MAX(lastmodified) FROM rra y WHERE
			x.service = y.service
		)`)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	srr := slib.RRAsResponse{}
	srr.Results = make([]slib.RRAService, 0)
	for rows.Next() {
		var s slib.RRAService
		err = rows.Scan(&s.ID, &s.Name, &s.DefData)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
		srr.Results = append(srr.Results, s)
	}
	err = rows.Err()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	buf, err := json.Marshal(&srr)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	fmt.Fprint(rw, string(buf))
}
