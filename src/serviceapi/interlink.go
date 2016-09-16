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
	"database/sql"
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
	HOST_OWNERSHIP
	OWNER_ADD
	ASSOCIATE_AWS
	HOST_AWSSQL_LINK_SYSGROUP
)

// Defines a rule in the interlink system
type interlinkRule struct {
	ruleid   int
	ruletype int

	srcHostMatch     string
	srcSysGroupMatch string
	srcAWSSQLMatch   string

	destServiceMatch  string
	destSysGroupMatch string

	srcWebsiteMatch  string
	destWebsiteMatch string

	destOwnerMatch struct {
		Operator string
		Team     string
	}

	destV2BOverride sql.NullString
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

// Execute any owner add operations
func interlinkRunOwnerAdd(op opContext) error {
	rows, err := op.Query(`SELECT destoperatormatch, destteammatch FROM interlinks
		WHERE ruletype = $1`, OWNER_ADD)
	if err != nil {
		return err
	}
	type os struct {
		operator string
		team     string
	}
	var osl []os
	for rows.Next() {
		var nos os
		err = rows.Scan(&nos.operator, &nos.team)
		if err != nil {
			rows.Close()
			return err
		}
		osl = append(osl, nos)
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	for _, o := range osl {
		_, err := op.Exec(`INSERT INTO assetowners
		(operator, team) SELECT $1, $2
		WHERE NOT EXISTS (
			SELECT 1 FROM assetowners WHERE operator = $3 AND
			team = $4
		)`, o.operator, o.team, o.operator, o.team)
		if err != nil {
			return err
		}
	}
	return nil
}

// Link hosts with owners based on host match and operator/team
func interlinkHostOwnerLink(op opContext) error {
	// Run the rules in reverse order here so rules specified earlier in the
	// rule set take precedence
	rows, err := op.Query(`SELECT srchostmatch, destoperatormatch,
		destteammatch, destv2boverride FROM interlinks
		WHERE ruletype = $1 ORDER BY ruleid DESC`, HOST_OWNERSHIP)
	if err != nil {
		return err
	}
	type os struct {
		srchm    string
		operator string
		team     string
		v2b      sql.NullString
	}
	var resset []os
	for rows.Next() {
		nr := os{}
		err = rows.Scan(&nr.srchm, &nr.operator, &nr.team, &nr.v2b)
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
			SET ownerid = (SELECT ownerid FROM assetowners
			WHERE operator = $1 AND team = $2 LIMIT 1) WHERE
			hostname ~* $3 AND assettype = 'host'`, r.operator,
			r.team, r.srchm)
		if err != nil {
			return err
		}
		// If a V2B key override was set for this entry, apply it as well
		if r.v2b.Valid && r.v2b.String != "" {
			_, err = op.Exec(`UPDATE asset
			SET v2boverride = $1 WHERE
			hostname ~* $2 AND assettype = 'host'`, r.v2b.String,
				r.srchm)
			if err != nil {
				return err
			}
		} else {
			_, err = op.Exec(`UPDATE asset
			SET v2boverride = NULL WHERE
			hostname ~* $1 AND assettype = 'host'`, r.srchm)
			if err != nil {
				return err
			}
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

// Link hosts with system groups using available AWS metadata
func interlinkHostAWSSQLSysGroupLink(op opContext) error {
	rows, err := op.Query(`SELECT srcawssqlmatch, destsysgroupmatch FROM interlinks
		WHERE ruletype = $1`, HOST_AWSSQL_LINK_SYSGROUP)
	if err != nil {
		return err
	}
	type linkResSet struct {
		srcawssm string
		dstsgm   string
	}
	var resset []linkResSet
	for rows.Next() {
		nr := linkResSet{}
		err = rows.Scan(&nr.srcawssm, &nr.dstsgm)
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
		buf := `UPDATE asset x
			SET sysgroupid = (SELECT sysgroupid FROM sysgroup
			WHERE name ~* $1 LIMIT 1)
			FROM assetawsmeta y
			WHERE x.assettype = 'host' AND
			x.assetawsmetaid = y.assetawsmetaid AND
			%v`
		qs := fmt.Sprintf(buf, r.srcawssm)
		_, err = op.Exec(qs, r.dstsgm)
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

func interlinkAssociateAWS(op opContext) error {
	var v int
	// Just run it once if the rule is present in the rule set
	err := op.QueryRow(`SELECT 1 FROM interlinks WHERE
		ruletype = $1`, ASSOCIATE_AWS).Scan(&v)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		} else {
			return err
		}
	}
	_, err = op.Exec(`UPDATE asset x
		SET assetawsmetaid = (SELECT assetawsmetaid FROM assetawsmeta y
		WHERE x.hostname = y.private_dns) WHERE
		assetid IN (
			SELECT assetid FROM asset a
			JOIN assetawsmeta b ON
			a.hostname = b.private_dns
		)`)
	if err != nil {
		return err
	}
	slist := strings.Split(cfg.Interlink.AWSStripDNSSuffixList, " ")
	for _, x := range slist {
		xv := "%" + x
		_, err = op.Exec(`UPDATE asset x
		SET assetawsmetaid = (SELECT assetawsmetaid FROM assetawsmeta y
		WHERE x.hostname = substring(y.private_dns from '[^\.]*')
		AND y.private_dns LIKE $1) WHERE
		assetid IN (
			SELECT assetid FROM asset a
			JOIN assetawsmeta b ON
			a.hostname = substring(b.private_dns from '[^\.]*') AND
			b.private_dns LIKE $2
		)`, xv, xv)
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
	// Run owner adds
	err = interlinkRunOwnerAdd(op)
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
	// Run host awssqlmatch to system group linkage
	err = interlinkHostAWSSQLSysGroupLink(op)
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	// Run host to owner linkage
	err = interlinkHostOwnerLink(op)
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
	err = interlinkAssociateAWS(op)
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
		} else if len(tokens) == 4 && tokens[0] == "add" && tokens[1] == "owner" {
			nr.ruletype = OWNER_ADD
			nr.destOwnerMatch.Operator = tokens[2]
			nr.destOwnerMatch.Team = tokens[3]
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
		} else if len(tokens) >= 6 && tokens[0] == "host" &&
			tokens[1] == "awssqlmatch" {
			// We can have a variable number of arguments in the source match component
			// here, so we need to isolate them.
			var lel int
			for i := 0; i < len(tokens); i++ {
				if len(tokens)-i > 2 && tokens[i] == "link" &&
					tokens[i+1] == "sysgroup" {
					lel = i
					break
				}
			}
			if lel != 0 {
				mstr := strings.Join(tokens[2:lel], " ")
				nr.ruletype = HOST_AWSSQL_LINK_SYSGROUP
				nr.srcAWSSQLMatch = mstr
				nr.destSysGroupMatch = tokens[lel+2]
				valid = true
			}
		} else if len(tokens) >= 6 && tokens[0] == "host" &&
			tokens[1] == "matches" && tokens[3] == "ownership" {
			nr.ruletype = HOST_OWNERSHIP
			nr.srcHostMatch = tokens[2]
			nr.destOwnerMatch.Operator = tokens[4]
			nr.destOwnerMatch.Team = tokens[5]
			if len(tokens) == 7 {
				nr.destV2BOverride.String = tokens[6]
				nr.destV2BOverride.Valid = true
			}
			valid = true
		} else if len(tokens) == 6 && tokens[0] == "website" &&
			tokens[1] == "matches" && tokens[3] == "link" && tokens[4] == "sysgroup" {
			nr.ruletype = WEBSITE_LINK_SYSGROUP
			nr.srcWebsiteMatch = tokens[2]
			nr.destSysGroupMatch = tokens[5]
			valid = true
		} else if len(tokens) == 3 && tokens[0] == "associate" && tokens[1] == "aws" &&
			tokens[2] == "privatedns" {
			nr.ruletype = ASSOCIATE_AWS
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
		case HOST_AWSSQL_LINK_SYSGROUP:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype, srcawssqlmatch,
				destsysgroupmatch) VALUES ($1, $2, $3)`, x.ruletype,
				x.srcAWSSQLMatch, x.destSysGroupMatch)
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
		case HOST_OWNERSHIP:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype, srchostmatch,
				destoperatormatch, destteammatch, destv2boverride)
				VALUES ($1, $2, $3, $4, $5)`, x.ruletype, x.srcHostMatch,
				x.destOwnerMatch.Operator, x.destOwnerMatch.Team,
				x.destV2BOverride)
			if err != nil {
				e := op.rollback()
				if e != nil {
					panic(e)
				}
				return err
			}
		case OWNER_ADD:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype, destoperatormatch,
				destteammatch)
				VALUES ($1, $2, $3)`, x.ruletype, x.destOwnerMatch.Operator,
				x.destOwnerMatch.Team)
			if err != nil {
				e := op.rollback()
				if e != nil {
					panic(e)
				}
				return err
			}
		case ASSOCIATE_AWS:
			_, err = op.Exec(`INSERT INTO interlinks (ruletype)
				VALUES ($1)`, x.ruletype)
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
