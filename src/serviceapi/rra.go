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
	"net/http"
	slib "servicelib"
)

func getRRA(op opContext, rraid string) (slib.RRAService, error) {
	var rr slib.RRAService

	rows, err := op.Query(`SELECT rraid, service,
		ari, api, afi, cri, cpi, cfi,
		iri, ipi, ifi, datadefault
		FROM rra WHERE rraid = $1`, rraid)
	if err != nil {
		return rr, err
	}
	if !rows.Next() {
		return rr, nil
	}
	err = rows.Scan(&rr.ID, &rr.Name, &rr.AvailRep, &rr.AvailPrd,
		&rr.AvailFin, &rr.ConfiRep, &rr.ConfiPrd, &rr.ConfiFin,
		&rr.IntegRep, &rr.IntegPrd, &rr.IntegFin, &rr.DefData)
	if err != nil {
		return rr, nil
	}
	err = rows.Close()
	if err != nil {
		return rr, err
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
			return err
		}
		sg, err := getSysGroup(op, sgid)
		if err != nil {
			return err
		}
		if sg.Name == "" {
			continue
		}
		r.SupportGrps = append(r.SupportGrps, sg)
	}
	return nil
}

func serviceGetRRA(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	rraid := req.FormValue("id")

	op := opContext{}
	op.newContext(dbconn, false)

	r, err := getRRA(op, rraid)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}

	buf, err := json.Marshal(&r)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

func serviceRRAs(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false)

	rows, err := op.Query(`SELECT rraid, service, datadefault
		FROM rra`)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	srr := slib.RRAsResponse{}
	srr.Results = make([]slib.RRAService, 0)
	for rows.Next() {
		var s slib.RRAService
		err = rows.Scan(&s.ID, &s.Name, &s.DefData)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		srr.Results = append(srr.Results, s)
	}

	buf, err := json.Marshal(&srr)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}

	fmt.Fprint(rw, string(buf))
}
