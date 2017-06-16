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
	"errors"
	"os"
	"strings"
	"time"
)

const (
	_ = iota
	ASSETGROUP_ADD
	ASSETGROUP_LINK_SERVICE
	HOST_LINK_ASSETGROUP
	WEBSITE_ADD
	WEBSITE_LINK_ASSETGROUP
	HOST_OWNERSHIP
	OWNER_ADD
)

// Defines a rule in the interlink system
type interlinkRule struct {
	ruleid   int
	ruletype int

	srcHostMatch       string
	srcAssetGroupMatch string
	srcAWSSQLMatch     string

	destServiceMatch    string
	destAssetGroupMatch string

	srcWebsiteMatch  string
	destWebsiteMatch string

	destOwnerMatch struct {
		Operator string
		Team     string
	}

	destTriageOverride string
}

var interlinkLastLoad time.Time

// XXX Note regarding these functions; the updates and changes occur in a
// transaction. With the existing sql/pq implementation this requires a
// single query to be in flight at a time, and we need to drain the results
// of select queries to make sure they do not overlap with other operations.

// Execute any asset group add operations
func interlinkRunAssetGroupAdd(op opContext, rules []interlinkRule) error {
	for _, x := range rules {
		_, err := op.Exec(`INSERT INTO assetgroup
		(name) SELECT $1
		WHERE NOT EXISTS (
			SELECT 1 FROM assetgroup WHERE name = $2
		)`, x.destAssetGroupMatch, x.destAssetGroupMatch)
		if err != nil {
			return err
		}
	}
	return nil
}

// Execute any owner add operations
func interlinkRunOwnerAdd(op opContext, rules []interlinkRule) error {
	for _, o := range rules {
		operator := o.destOwnerMatch.Operator
		team := o.destOwnerMatch.Team
		_, err := op.Exec(`INSERT INTO assetowners
		(operator, team) SELECT $1, $2
		WHERE NOT EXISTS (
			SELECT 1 FROM assetowners WHERE operator = $3 AND
			team = $4
		)`, operator, team, operator, team)
		if err != nil {
			return err
		}
	}
	return nil
}

// Link hosts with owners based on host match and operator/team
func interlinkHostOwnerLink(op opContext, rules []interlinkRule) error {
	for _, r := range rules {
		_, err := op.Exec(`UPDATE asset
			SET ownerid = (SELECT ownerid FROM assetowners
			WHERE operator = $1 AND team = $2) WHERE
			name ~* $3 AND assettype = 'hostname'`,
			r.destOwnerMatch.Operator, r.destOwnerMatch.Team,
			r.srcHostMatch)
		if err != nil {
			return err
		}
		// If a V2B key override was set for this entry, apply it as well
		if r.destTriageOverride != "" {
			_, err = op.Exec(`UPDATE asset
			SET triageoverride = $1 WHERE
			name ~* $2 AND assettype = 'hostname'`,
				r.destTriageOverride, r.srcHostMatch)
			if err != nil {
				return err
			}
		} else {
			_, err = op.Exec(`UPDATE asset
			SET triageoverride = NULL WHERE
			name ~* $1 AND assettype = 'hostname'`, r.srcHostMatch)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Link websites with system groups based on site match and system group name match
func interlinkWebsiteAssetGroupLink(op opContext, rules []interlinkRule) error {
	for _, r := range rules {
		_, err := op.Exec(`UPDATE asset
			SET assetgroupid = (SELECT assetgroupid FROM assetgroup
			WHERE name = $1) WHERE
			name ~* $2 AND assettype = 'website'`,
			r.destAssetGroupMatch, r.srcWebsiteMatch)
		if err != nil {
			return err
		}
	}
	return nil
}

// Link hosts with system groups based on host match and system group name match
func interlinkHostAssetGroupLink(op opContext, rules []interlinkRule) error {
	for _, r := range rules {
		_, err := op.Exec(`UPDATE asset
			SET assetgroupid = (SELECT assetgroupid FROM assetgroup
			WHERE name = $1) WHERE
			name ~* $2 AND assettype = 'hostname'`,
			r.destAssetGroupMatch, r.srcHostMatch)
		if err != nil {
			return err
		}
	}
	return nil
}

// Link system groups with supported services based on group and service name
func interlinkAssetGroupServiceLink(op opContext, rules []interlinkRule) error {
	for _, r := range rules {
		_, err := op.Exec(`DELETE FROM rra_assetgroup
			WHERE assetgroupid = (SELECT assetgroupid FROM assetgroup
			WHERE name = $1)`, r.srcAssetGroupMatch)
		if err != nil {
			return err
		}
		_, err = op.Exec(`INSERT INTO rra_assetgroup (rraid, assetgroupid)
			SELECT rraid, (
				SELECT assetgroupid FROM assetgroup WHERE name = $1
			) FROM rra WHERE service ~* $2`, r.srcAssetGroupMatch,
			r.destServiceMatch)
		if err != nil {
			return err
		}
	}
	return nil
}

func getRulesType(rules []interlinkRule, ruletype int) (ret []interlinkRule) {
	for _, x := range rules {
		if x.ruletype == ruletype {
			ret = append(ret, x)
		}
	}
	return
}

// Run interlink rules
func interlinkRunRules(rules []interlinkRule) error {
	op := opContext{}
	op.newContext(dbconn, true, "interlink")

	var ts time.Time
	stim := func() {
		ts = time.Now()
	}
	etim := func(n string) {
		logf("interlink %v took %v", n, time.Now().Sub(ts))
	}

	logf("interlink: processing")

	// Run system group adds
	stim()
	err := interlinkRunAssetGroupAdd(op, getRulesType(rules, ASSETGROUP_ADD))
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	etim("AssetGroupAdd")
	// Run owner adds
	stim()
	err = interlinkRunOwnerAdd(op, getRulesType(rules, OWNER_ADD))
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	etim("OwnerAdd")
	// Run host to system group linkage
	stim()
	err = interlinkHostAssetGroupLink(op, getRulesType(rules, HOST_LINK_ASSETGROUP))
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	etim("HostAssetGroupLink")
	// Run host to owner linkage
	stim()
	err = interlinkHostOwnerLink(op, getRulesType(rules, HOST_OWNERSHIP))
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	etim("HostOwnerLink")
	// Run website to system group linkage
	stim()
	err = interlinkWebsiteAssetGroupLink(op, getRulesType(rules, WEBSITE_LINK_ASSETGROUP))
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	etim("WebsiteAssetGroupLink")
	// Run system group to service linkage
	stim()
	err = interlinkAssetGroupServiceLink(op, getRulesType(rules, ASSETGROUP_LINK_SERVICE))
	if err != nil {
		e := op.rollback()
		if e != nil {
			panic(e)
		}
		return err
	}
	etim("AssetGroupServiceLink")
	err = op.commit()
	if err != nil {
		panic(err)
	}
	return nil
}

// Load interlink rules from the file system and return the rule set
func interlinkLoadRules() ([]interlinkRule, error) {
	var rules []interlinkRule

	fd, err := os.Open(cfg.Interlink.RulePath)
	if err != nil {
		return rules, err
	}
	defer fd.Close()

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
		if len(tokens) < 2 {
			return rules, errors.New("interlink rule without enough arguments")
		}
		valid := false
		if len(tokens) == 3 && tokens[0] == "add" && tokens[1] == "assetgroup" {
			nr.ruletype = ASSETGROUP_ADD
			nr.destAssetGroupMatch = tokens[2]
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
		} else if len(tokens) == 6 && tokens[0] == "assetgroup" &&
			tokens[1] == "matches" && tokens[3] == "link" && tokens[4] == "service" {
			nr.ruletype = ASSETGROUP_LINK_SERVICE
			nr.srcAssetGroupMatch = tokens[2]
			nr.destServiceMatch = tokens[5]
			valid = true
		} else if len(tokens) == 6 && tokens[0] == "host" &&
			tokens[1] == "matches" && tokens[3] == "link" && tokens[4] == "assetgroup" {
			nr.ruletype = HOST_LINK_ASSETGROUP
			nr.srcHostMatch = tokens[2]
			nr.destAssetGroupMatch = tokens[5]
			valid = true
		} else if len(tokens) >= 6 && tokens[0] == "host" &&
			tokens[1] == "matches" && tokens[3] == "ownership" {
			nr.ruletype = HOST_OWNERSHIP
			nr.srcHostMatch = tokens[2]
			nr.destOwnerMatch.Operator = tokens[4]
			nr.destOwnerMatch.Team = tokens[5]
			if len(tokens) == 7 {
				nr.destTriageOverride = tokens[6]
			}
			valid = true
		} else if len(tokens) == 6 && tokens[0] == "website" &&
			tokens[1] == "matches" && tokens[3] == "link" && tokens[4] == "assetgroup" {
			nr.ruletype = WEBSITE_LINK_ASSETGROUP
			nr.srcWebsiteMatch = tokens[2]
			nr.destAssetGroupMatch = tokens[5]
			valid = true
		}
		if !valid {
			return rules, errors.New("syntax error in interlink rules")
		}
		rules = append(rules, nr)
	}

	logf("interlink: loaded %v rules", len(rules))
	return rules, nil
}

func interlinkManager() {
	rules, err := interlinkLoadRules()
	if err != nil {
		logf("error loading interlink rules: %v", err)
		return
	}
	err = interlinkRunRules(rules)
	if err != nil {
		logf("error running interlink rules: %v", err)
	}
}
