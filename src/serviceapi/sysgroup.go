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
)

// Add a system group to the database if it does not exist
func addSysGroup(op opContext, name string) error {
	_, err := op.Exec(`INSERT INTO sysgroup
		(name) SELECT $1
		WHERE NOT EXISTS (
			SELECT 1 FROM sysgroup WHERE name = $2
		)`, name, name)
	if err != nil {
		return err
	}
	return nil
}

func getSysGroup(op opContext, sgid string) (slib.SystemGroup, error) {
	var sg slib.SystemGroup

	rows, err := op.Query(`SELECT sysgroupid, name
		FROM sysgroup WHERE sysgroupid = $1`, sgid)
	if err != nil {
		return sg, err
	}
	if !rows.Next() {
		return sg, nil
	}
	err = rows.Scan(&sg.ID, &sg.Name)
	if err != nil {
		return sg, err
	}
	err = rows.Close()
	if err != nil {
		return sg, err
	}

	return sg, nil
}

func hostDynSysgroup(op opContext, hn string) (int, error) {
	rows, err := op.Query(`SELECT m.sysgroupid FROM
		hostmatch as m WHERE
		$1 ~* m.expression`, hn)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if rows.Next() {
		var sgid sql.NullInt64
		err = rows.Scan(&sgid)
		if err != nil {
			return 0, err
		}
		if sgid.Valid {
			return int(sgid.Int64), nil
		}
	}
	return 0, nil
}

func sysGroupAddMeta(op opContext, s *slib.SystemGroup) error {
	s.Host = make([]slib.Host, 0)
	s.HostMatch = make([]slib.HostMatch, 0)

	// Grab any hosts that have been statically mapped to this group.
	rows, err := op.Query(`SELECT hostid, hostname, comment, lastused
		FROM host WHERE sysgroupid = $1`, s.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h slib.Host
		err = rows.Scan(&h.ID, &h.Hostname, &h.Comment, &h.LastUsed)
		if err != nil {
			return err
		}
		err = hostAddComp(op, &h)
		if err != nil {
			return err
		}
		s.Host = append(s.Host, h)
	}

	// Include dynamic entries here based on matching with expressions
	// in the hostmatch table. Note we don't do this for normal static
	// hosts as it is assumed these would be linked manually when they
	// are added.
	rows, err = op.Query(`SELECT h.hostid, h.hostname,
		h.comment, h.lastused FROM
		host as h, hostmatch as m WHERE
		h.hostname ~* m.expression AND
		h.dynamic = true AND
		m.sysgroupid = $1`, s.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h slib.Host
		err = rows.Scan(&h.ID, &h.Hostname, &h.Comment, &h.LastUsed)
		if err != nil {
			rows.Close()
			return err
		}
		h.Dynamic = true
		err = hostAddComp(op, &h)
		if err != nil {
			rows.Close()
			return err
		}
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
		if err != nil {
			rows.Close()
			return err
		}
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
	op.newContext(dbconn, false, req.RemoteAddr)

	sg, err := getSysGroup(op, sgid)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	if sg.Name == "" {
		http.NotFound(rw, req)
		return
	}
	err = sysGroupAddMeta(op, &sg)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	buf, err := json.Marshal(&sg)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

func serviceSysGroups(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	rows, err := op.db.Query(`SELECT sysgroupid FROM sysgroup`)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	sgr := slib.SystemGroupsResponse{}
	sgr.Results = make([]slib.SystemGroup, 0)
	for rows.Next() {
		var sgid string
		err = rows.Scan(&sgid)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
		sg, err := getSysGroup(op, sgid)
		if err != nil {
			op.logf(err.Error())
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
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprint(rw, string(buf))
}
