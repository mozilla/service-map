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

// getOwner returns Owner ID oid from the database
func getOwner(op opContext, oid int) (ret slib.Owner, err error) {
	err = op.QueryRow(`SELECT ownerid, operator, team
		FROM assetowners WHERE ownerid = $1`, oid).Scan(&ret.ID, &ret.Operator, &ret.Team)
	if err != nil {
		return
	}
	return
}

// getOwners returns all owners from database
func getOwners(op opContext) (ret []slib.Owner, err error) {
	rows, err := op.Query(`SELECT ownerid, operator, team
		FROM assetowners`)
	if err != nil {
		return
	}
	for rows.Next() {
		var nown slib.Owner
		err = rows.Scan(&nown.ID, &nown.Operator, &nown.Team)
		if err != nil {
			rows.Close()
			return ret, err
		}
		ret = append(ret, nown)
	}
	err = rows.Err()
	if err != nil {
		return
	}
	return
}

// serviceHostOwner is the API entry point to fetch known ownership information
// for a host type asset
func serviceHostOwner(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	assethostname := req.FormValue("hostname")
	if assethostname == "" {
		op.logf("invalid hostname")
		http.Error(rw, "invalid hostname", 400)
		return
	}

	alist, err := getAssetHostname(op, assethostname)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving owner info", 500)
		return
	}

	// XXX We only return a single owner entry here for the asset, even
	// though getAssetHostname could return more than one asset if there are a
	// more than one asset in the database with the same hostname but a different
	// zone ID.
	//
	// This should be adjusted in the future but for now we just return the first
	// result we get.
	if len(alist) == 0 {
		http.Error(rw, "no matching assets found", 404)
		return
	}
	a := alist[0]
	buf, err := json.Marshal(&a.Owner)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving owner info", 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

// serviceOwners is the API entry point to fetch raw owner map
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
		zone, operator, team, triageoverride
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
