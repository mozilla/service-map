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
	"net/http"
)

// Returns data via legacy endpoints for consumption by tools which require
// map data formatted in certain way
func serviceVulnAuto(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	var (
		ret                slib.VulnAutoList
		srchm              string
		destoper, destteam string
		destv2boverride    sql.NullString
	)

	// Extract ownership information from the interlink table to
	// build the response
	rows, err := op.Query(`SELECT srchostmatch,
		destoperatormatch, destteammatch, destv2boverride
		FROM interlinks
		WHERE ruletype = $1 ORDER BY ruleid`, HOST_OWNERSHIP)
	for rows.Next() {
		err = rows.Scan(&srchm, &destoper, &destteam, &destv2boverride)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
		nent := slib.VulnAuto{
			Team:     destteam,
			Operator: destoper,
			Match:    srchm,
			V2BKey:   destoper + "-" + destteam,
		}
		if destv2boverride.Valid && destv2boverride.String != "" {
			nent.V2BKey = destv2boverride.String
		}
		ret.VulnAuto = append(ret.VulnAuto, nent)
	}
	err = rows.Err()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	buf, err := json.Marshal(&ret)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}
