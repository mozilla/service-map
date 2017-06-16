// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// API entry point to fetch raw owner map
//
// This is a legacy function that supports a few integrated tools, providing a
// simple method to obtain asset ownership details.
func serviceOwners(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	type respent struct {
		name      string
		assettype string
		zone      string
		operator  string
		team      string
		triagekey string
	}
	var (
		resplist       []respent
		operator       sql.NullString
		team           sql.NullString
		triageoverride sql.NullString
	)
	rows, err := op.Query(`SELECT name, assettype,
		operator, team, triageoverride
		FROM asset LEFT OUTER JOIN assetowners ON
		(asset.ownerid = assetowners.ownerid)
		ORDER BY name`)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving owner list", 500)
		return
	}
	for rows.Next() {
		x := respent{}
		err = rows.Scan(&x.name, &x.assettype, &x.zone,
			&operator, &team, &triageoverride)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, "error retrieving owner list", 500)
			return
		}
		if !operator.Valid {
			x.operator = "unset"
		} else {
			x.operator = operator.String
		}
		if !team.Valid {
			x.team = "unset"
		} else {
			x.team = team.String
		}
		if !triageoverride.Valid {
			x.triagekey = x.operator + "-" + x.team
		} else {
			x.triagekey = triageoverride.String
		}
		resplist = append(resplist, x)
	}
	err = rows.Err()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving owner list", 500)
		return
	}

	fmt.Fprintf(rw, "# name type zone operator team triagekey\n")
	for _, x := range resplist {
		fmt.Fprintf(rw, "%v %v %v %v %v %v\n", x.name, x.assettype,
			x.zone, x.operator, x.team, x.triagekey)
	}
}
