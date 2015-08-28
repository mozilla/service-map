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

func getSysGroup(op opContext, sgid string) (slib.SystemGroup, error) {
	var sg slib.SystemGroup

	rows, err := op.Query(`SELECT sysgroupid, name, environment
		FROM sysgroup WHERE sysgroupid = $1`, sgid)
	if err != nil {
		return sg, err
	}
	if !rows.Next() {
		return sg, nil
	}
	err = rows.Scan(&sg.ID, &sg.Name, &sg.Environment)
	if err != nil {
		return sg, err
	}
	err = rows.Close()
	if err != nil {
		return sg, err
	}

	return sg, nil
}

func sysGroupAddMeta(op opContext, s *slib.SystemGroup) error {
	s.Host = make([]slib.Host, 0)
	s.HostMatch = make([]slib.HostMatch, 0)

	// Grab any hosts that have been statically mapped to this group.
	rows, err := op.Query(`SELECT hostid, hostname, comment FROM
		host WHERE sysgroupid = $1`, s.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h slib.Host
		err = rows.Scan(&h.ID, &h.Hostname, &h.Comment)
		s.Host = append(s.Host, h)
	}

	// Grab any expressions for dynamic host mapping.
	rows, err = op.Query(`SELECT hostmatchid, expression, comment FROM
		hostmatch WHERE sysgroupid = $1`, s.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h slib.HostMatch
		err = rows.Scan(&h.ID, &h.Expression, &h.Comment)
		s.HostMatch = append(s.HostMatch, h)
	}

	return nil
}

func serviceGetSysGroup(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	sgid := req.FormValue("id")
	if sgid == "" {
		http.Error(rw, "must specify a valid system group id", 500)
		return
	}

	op := opContext{}
	op.newContext(dbconn, false)

	sg, err := getSysGroup(op, sgid)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	if sg.Name == "" {
		http.NotFound(rw, req)
		return
	}
	err = sysGroupAddMeta(op, &sg)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}

	buf, err := json.Marshal(&sg)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

func serviceSysGroups(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false)

	rows, err := op.db.Query(`SELECT sysgroupid FROM sysgroup`)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	sgr := slib.SystemGroupsResponse{}
	sgr.Results = make([]slib.SystemGroup, 0)
	for rows.Next() {
		var sgid string
		err = rows.Scan(&sgid)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		sg, err := getSysGroup(op, sgid)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		if sg.Name == "" {
			continue
		}
		sgr.Results = append(sgr.Results, sg)
	}

	buf, err := json.Marshal(&sgr)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprint(rw, string(buf))
}
