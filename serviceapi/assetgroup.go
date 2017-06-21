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

// Get all asset groups
func getAssetGroups(op opContext) (ret []slib.AssetGroup, err error) {
	rows, err := op.Query(`SELECT assetgroupid, name
		FROM assetgroup`)
	if err != nil {
		return
	}
	for rows.Next() {
		var ngrp slib.AssetGroup
		err = rows.Scan(&ngrp.ID, &ngrp.Name)
		if err != nil {
			rows.Close()
			return ret, err
		}
		ret = append(ret, ngrp)
	}
	err = rows.Err()
	if err != nil {
		return
	}
	return
}

// API entry point to retrieve a given asset group
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

	var err error
	agr := slib.AssetGroupsResponse{}
	agr.Groups, err = getAssetGroups(op)
	if err != nil {
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
