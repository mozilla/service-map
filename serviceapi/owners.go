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
func serviceOwners(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	type respent struct {
		hostname string
		operator string
		team     string
		v2bkey   string
	}
	var (
		resplist    []respent
		operator    sql.NullString
		team        sql.NullString
		v2boverride sql.NullString
	)
	rows, err := op.Query(`SELECT hostname, operator, team, v2boverride
		FROM asset LEFT OUTER JOIN assetowners ON
		(asset.ownerid = assetowners.ownerid)
		WHERE assettype = 'host' ORDER BY hostname`)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	for rows.Next() {
		x := respent{}
		err = rows.Scan(&x.hostname, &operator, &team, &v2boverride)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
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
		if !v2boverride.Valid {
			x.v2bkey = x.operator + "-" + x.team
		} else {
			x.v2bkey = v2boverride.String
		}
		resplist = append(resplist, x)
	}
	err = rows.Err()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	fmt.Fprintf(rw, "# host operator team v2bkey\n")
	for _, x := range resplist {
		fmt.Fprintf(rw, "%v %v %v %v\n", x.hostname, x.operator,
			x.team, x.v2bkey)
	}
}
