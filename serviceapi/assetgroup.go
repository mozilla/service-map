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
	slib "github.com/mozilla/service-map/servicelib"
	"net/http"
	"strconv"
)

// Return an AssetGroup given an asset group ID
func getAssetGroup(op opContext, agid int) (ret slib.AssetGroup, err error) {
	err = op.QueryRow(`SELECT assetgroupid, name
		FROM assetgroup WHERE assetgroupid = $1`, agid).Scan(&ret.ID, &ret.Name)
	return
}

// API entry point to retrieve a given system group
func serviceGetAssetGroup(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	req.ParseForm()
	agidstr := req.FormValue("id")
	if agidstr == "" {
		http.Error(rw, "invalid asset group id", 400)
		return
	}
	agid, err := strconv.Atoi(agidstr)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "invalid asset group id", 400)
		return
	}

	ag, err := getAssetGroup(op, agid)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving asset group", 500)
		return
	}

	buf, err := json.Marshal(&ag)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving asset group", 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

// API entry point to retrieve all asset groups
func serviceAssetGroups(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	rows, err := op.db.Query(`SELECT assetgroupid FROM assetgroup`)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving asset groups", 500)
		return
	}
	agr := slib.AssetGroupsResponse{}
	agr.Groups = make([]slib.AssetGroup, 0)
	for rows.Next() {
		var agid int
		err = rows.Scan(&agid)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, "error retrieving asset groups", 500)
			return
		}
		ag, err := getAssetGroup(op, agid)
		if err != nil {
			rows.Close()
			op.logf(err.Error())
			http.Error(rw, "error retrieving asset groups", 500)
			return
		}
		agr.Groups = append(agr.Groups, ag)
	}
	if err = rows.Err(); err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving asset groups", 500)
		return
	}

	buf, err := json.Marshal(&agr)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving asset groups", 500)
		return
	}
	fmt.Fprint(rw, string(buf))
}
