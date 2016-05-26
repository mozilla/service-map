// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

// Related to the interlink rule set parser and application of the rules

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	_ = iota
	SYSGROUP_ADD
	SYSGROUP_LINK_SERVICE
	HOST_LINK_SYSGROUP
	WEBSITE_ADD
	WEBSITE_LINK_SYSGROUP
)

// Defines a rule in the interlink system
type interlinkRule struct {
	ruleid   int
	ruletype int

	srcHostMatch     string
	srcSysGroupMatch string

	destServiceMatch  string
	destSysGroupMatch string

	srcWebsiteMatch  string
	destWebsiteMatch string
}

var interlinkLastLoad time.Time

// XXX Note regarding these functions; the updates and changes occur in a
// transaction. With the existing sql/pq implementation this requires a
// single query to be in flight at a time, and we need to drain the results
// of select queries to make sure they do not overlap with other operations.

// Execute any system group add operations
func interlinkRunSysGroupAdd(op opContext) error {
	rows, err := op.Query(`SELECT destsysgroupmatch FROM interlinks
		WHERE ruletype = $1`, SYSGROUP_ADD)
	if err != nil {
		return err
	}
	var sgnames []string
	for rows.Next() {
		var nsg string
		err = rows.Scan(&nsg)
		if err != nil {
			rows.Close()
			return err
		}
		sgnames = append(sgnames, nsg)
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	for _, s := range sgnames {
		_, err := op.Exec(`INSERT INTO sysgroup
		(name) SELECT $1
		WHERE NOT EXISTS (
			SELECT 1 FROM sysgroup WHERE name = $2
		)`, s, s)
		if err != nil {
			return err
		}
	}
	return nil
}

// Execute any website add operations
func interlinkRunWebsiteAdd(op opContext) error {
	rows, err := op.Query(`SELECT destwebsitematch FROM interlinks
		WHERE ruletype = $1`, WEBSITE_ADD)
	if err != nil {
		return err
	}
	var wsnames []string
	for rows.Next() {
		var nws string
		err = rows.Scan(&nws)
		if err != nil {
			rows.Close()
			return err
		}
		wsnames = append(wsnames, nws)
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	for _, x := range wsnames {
		err = updateWebsite(op, x, "interlink website", 100)
		if err != nil {
			return err
		}
	}
	return nil
}

// Link websites with system groups based on site match and system group name match
func interlinkWebsiteSysGroupLink(op opContext) error {
	rows, err := op.Query(`SELECT srcwebsitematch, destsysgroupmatch FROM interlinks
		WHERE ruletype = $1`, WEBSITE_LINK_SYSGROUP)
	if err != nil {
		return err
	}
	type linkResSet struct {
		srchm  string
		dstsgm string
	}
	var resset []linkResSet
	for rows.Next() {
		nr := linkResSet{}
		err = rows.Scan(&nr.srchm, &nr.dstsgm)
		if err != nil {
			rows.Close()
			return err
		}
		resset = append(resset, nr)
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	for _, r := range resset {
		_, err = op.Exec(`UPDATE asset
			SET sysgroupid = (SELECT sysgroupid FROM sysgroup
			WHERE name ~* $1 LIMIT 1) WHERE
			website ~* $2 AND assettype = 'website'`, r.dstsgm, r.srchm)
		if err != nil {
			return err
		}
	}
	return nil
}

// Link hosts with system groups based on host match and system group name match
func interlinkHostSysGroupLink(op opContext) error {
	rows, err := op.Query(`SELECT srchostmatch, destsysgroupmatch FROM interlinks
		WHERE ruletype = $1`, HOST_LINK_SYSGROUP)
	if err != nil {
		return err
	}
	type linkResSet struct {
		srchm  string
		dstsgm string
	}
	var resset []linkResSet
	for rows.Next() {
		nr := linkResSet{}
		err = rows.Scan(&nr.srchm, &nr.dstsgm)
		if err != nil {
			rows.Close()
			return err
		}
		resset = append(resset, nr)
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	for _, r := range resset {
		_, err = op.Exec(`UPDATE asset
			SET sysgroupid = (SELECT sysgroupid FROM sysgroup
			WHERE name ~* $1 LIMIT 1) WHERE
			hostname ~* $2 AND assettype = 'host'`, r.dstsgm, r.srchm)
		if err != nil {
			return err
		}
	}
	return nil
}

// Link system groups with supported services based on group and service name
func interlinkSysGroupServiceLink(op opContext) error {
	rows, err := op.Query(`SELECT sysgroupid, rraid FROM interlinks
		JOIN sysgroup ON sysgroup.name ~* srcsysgroupmatch
		JOIN rra ON rra.service ~* destservicematch
		WHERE ruletype = $1`, SYSGROUP_LINK_SERVICE)
	if err != nil {
		return err
	}
	type linkResSet struct {
		rraid int
		sgid  int
	}
	var resset []linkResSet
	for rows.Next() {
		nr := linkResSet{}
		err = rows.Scan(&nr.sgid, &nr.rraid)
		if err != nil {
			rows.Close()
			return err
		}
		resset = append(resset, nr)
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	var ftable []int
	for _, r := range resset {
		found := false
		for _, x := range ftable {
			if x == r.sgid {
				found = true
				break
			}
		}
		if !found {
			_, err = op.Exec(`DELETE FROM rra_sysgroup
				WHERE sysgroupid = $1`, r.sgid)
			if err != nil {
				return err
			}
			ftable = append(ftable, r.sgid)
		}
		_, err = op.Exec(`INSERT INTO rra_sysgroup
			VALUES ($1, $2)`, r.rraid, r.sgid)
		if err != nil {
			return err
		}
	}
	return nil
}

// Run interlink rules
func interlinkRunRules() error {
	op := opContext{}
	op.newContext(dbconn, true, "interlink")

	logf("interlink: processing")

	// Run system group adds
	err := interlinkRunSysGroupAdd(op)
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	// Run website adds
	err = interlinkRunWebsiteAdd(op)
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	// Run host to system group linkage
	err = interlinkHostSysGroupLink(op)
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	// Run website to system group linkage
	err = interlinkWebsiteSysGroupLink(op)
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	// Run system group to service linkage
	err = interlinkSysGroupServiceLink(op)
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	err = op.commit()
	if err != nil {
		panic(err)
	}
	return nil
}

// Load interlink rules from the file system and store them in the database
func interlinkLoadRules() error {
	ss, err := os.Stat(cfg.Interlink.RulePath)
	if err != nil {
		return err
	}

	// See if we need to load the rules
	if !interlinkLastLoad.IsZero() {
		if interlinkLastLoad.Equal(ss.ModTime()) {
			return nil
		}
	}

	fd, err := os.Open(cfg.Interlink.RulePath)
	if err != nil {
		return err
	}
	defer fd.Close()

	var rules []interlinkRule
	scnr := bufio.NewScanner(fd)
	for scnr.Scan() {
		buf := scnr.Text()
		if len(buf) == 0 {
			continue
		}
		tokens := strings.Split(buf, " ")

		if len(tokens) > 0 && tokens[0][0] == '#' {
			continue
		}

		var nr interlinkRule
		if len(tokens) < 3 {
			return fmt.Errorf("interlink rule without enough arguments")
		}
		valid := false
		if len(tokens) == 3 && tokens[0] == "add" && tokens[1] == "sysgroup" {
			nr.ruletype = SYSGROUP_ADD
			nr.destSysGroupMatch = tokens[2]
			valid = true
		} else if len(tokens) == 3 && tokens[0] == "add" && tokens[1] == "website" {
			nr.ruletype = WEBSITE_ADD
			nr.destWebsiteMatch = tokens[2]
			valid = true
		} else if len(tokens) == 6 && tokens[0] == "sysgroup" &&
			tokens[1] == "matches" && tokens[3] == "link" && tokens[4] == "service" {
			nr.ruletype = SYSGROUP_LINK_SERVICE
			nr.srcSysGroupMatch = tokens[2]
			nr.destServiceMatch = tokens[5]
			valid = true
		} else if len(tokens) == 6 && tokens[0] == "host" &&
			tokens[1] == "matches" && tokens[3] == "link" && tokens[4] == "sysgroup" {
			nr.ruletype = HOST_LINK_SYSGROUP
			nr.srcHostMatch = tokens[2]
			nr.destSysGroupMatch = tokens[5]
			valid = true
		} else if len(tokens) == 6 && tokens[0] == "website" &&
			tokens[1] == "matches" && tokens[3] == "link" && tokens[4] == "sysgroup" {
			nr.ruletype = WEBSITE_LINK_SYSGROUP
			nr.srcWebsiteMatch = tokens[2]
			nr.destSysGroupMatch = tokens[5]
			valid = true
		}
		if !valid {
			return fmt.Errorf("syntax error in interlink rules")
		}
		rules = append(rules, nr)
	}

	op := opContext{}
	op.newContext(dbconn, true, "interlink")
	_, err = op.Exec(`DELETE FROM interlinks`)
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	for _, x := range rules {
		switch x.ruletype {
		case SYSGROUP_ADD:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype, destsysgroupmatch)
				VALUES ($1, $2)`, x.ruletype, x.destSysGroupMatch)
			if err != nil {
				e := op.rollback()
				if e != nil {
					panic(e)
				}
				return err
			}
		case SYSGROUP_LINK_SERVICE:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype, srcsysgroupmatch,
				destservicematch) VALUES ($1, $2, $3)`, x.ruletype,
				x.srcSysGroupMatch, x.destServiceMatch)
			if err != nil {
				e := op.rollback()
				if e != nil {
					panic(e)
				}
				return err
			}
		case HOST_LINK_SYSGROUP:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype, srchostmatch,
				destsysgroupmatch) VALUES ($1, $2, $3)`, x.ruletype,
				x.srcHostMatch, x.destSysGroupMatch)
			if err != nil {
				e := op.rollback()
				if e != nil {
					panic(e)
				}
				return err
			}
		case WEBSITE_ADD:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype, destwebsitematch)
				VALUES ($1, $2)`, x.ruletype, x.destWebsiteMatch)
			if err != nil {
				e := op.rollback()
				if e != nil {
					panic(e)
				}
				return err
			}
		case WEBSITE_LINK_SYSGROUP:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype, srcwebsitematch,
				destsysgroupmatch) VALUES ($1, $2, $3)`, x.ruletype,
				x.srcWebsiteMatch, x.destSysGroupMatch)
			if err != nil {
				e := op.rollback()
				if e != nil {
					panic(e)
				}
				return err
			}
		}
	}
	err = op.commit()
	if err != nil {
		panic(err)
	}

	interlinkLastLoad = ss.ModTime()
	logf("interlink: loaded %v rules", len(rules))

	return nil
}

func interlinkManager() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in interlink routine: %v", e)
		}
	}()
	err := interlinkLoadRules()
	if err != nil {
		panic(err)
	}
	err = interlinkRunRules()
	if err != nil {
		panic(err)
	}
}
