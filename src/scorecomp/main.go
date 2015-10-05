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
	"flag"
	"fmt"
	"github.com/jvehent/gozdef"
	_ "github.com/lib/pq"
	elastigo "github.com/mattbaird/elastigo/lib"
	"os"
)

var dbconn *sql.DB

var compIndex = "complianceitems"
var esRequestMax = 1000000

// Return all hosts in scope for compliance scoring, right now we limit
// this to hosts that have been assigned a system group.
func getHosts(filter string) ([]string, error) {
	var ret []string
	var fcls0 string
	var fcls1 string
	if filter != "" {
		fcls0 = fmt.Sprintf("AND hostname !~* '%v'", filter)
		fcls1 = fmt.Sprintf("AND h.hostname !~* '%v'", filter)
	}
	query := `SELECT hostname FROM
		host WHERE sysgroupid IS NOT NULL %v UNION
		SELECT h.hostname FROM host as h,
		hostmatch as m WHERE
		h.hostname ~* m.expression AND
		m.sysgroupid IS NOT NULL %v`
	buf := fmt.Sprintf(query, fcls0, fcls1)

	rows, err := dbconn.Query(buf)
	if err != nil {
		return ret, err
	}
	for rows.Next() {
		var h string
		err = rows.Scan(&h)
		if err != nil {
			return ret, err
		}
		ret = append(ret, h)
	}
	fmt.Fprintf(os.Stdout, "Will process %v hosts\n", len(ret))
	return ret, nil
}

func scoreHost(h string, eshost string) error {
	conn := elastigo.NewConn()
	conn.Domain = eshost

	fmt.Fprintf(os.Stdout, "Processing %v...\n", h)
	template := `{
		"size": 1000000,
		"query": {
			"bool": {
				"must": [
				{
					"term": {
						"_type": "last_known_state"
					}
				},
				{
					"query_string": {
						"query": "target: \"%v\""
					}
				},
				{
					"range": {
						"utctimestamp": {
							"gt": "now-7d"
						}
					}
				}
				]
			}
		}
	}`
	tempbuf := fmt.Sprintf(template, h)
	res, err := conn.Search(compIndex, "last_known_state", nil, tempbuf)
	if err != nil {
		return err
	}
	if res.Hits.Len() == 0 {
		return nil
	}
	var ci []gozdef.ComplianceItem
	for _, x := range res.Hits.Hits {
		var nci gozdef.ComplianceItem
		err = json.Unmarshal(*x.Source, &nci)
		ci = append(ci, nci)
	}

	statusmap := make(map[string]bool)
	for _, x := range ci {
		if x.Compliance {
			statusmap[x.Check.Ref] = true
		} else {
			statusmap[x.Check.Ref] = false
		}
	}

	for x := range statusmap {
		iname := x
		ivalue := statusmap[x]
		_, err = dbconn.Exec(`INSERT INTO compscore
			(timestamp, hostid, checkref, status)
			VALUES
			(now() AT TIME ZONE 'utc',
			(SELECT hostid FROM host
			WHERE lower(hostname) = lower($1)),
			$2, $3)`, h, iname, ivalue)
		if err != nil {
			return err
		}
	}
	return nil
}

func dbInit() error {
	var err error
	dbconn, err = sql.Open("postgres", "dbname=servicemap host=/var/run/postgresql")
	if err != nil {
		return err
	}
	return nil
}

func main() {
	var eshost string
	var filter string
	flag.StringVar(&eshost, "e", "", "es hostname")
	flag.StringVar(&filter, "f", "", "host database filter")
	flag.Parse()

	if eshost == "" {
		fmt.Fprintf(os.Stderr, "error: must specify es hostname with -e\n")
		os.Exit(1)
	}

	err := dbInit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	hl, err := getHosts(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for _, x := range hl {
		err = scoreHost(x, eshost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
}
