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
	_ "github.com/lib/pq"
	elastigo "github.com/mattbaird/elastigo/lib"
	"os"
)

var dbconn *sql.DB

var compIndex = "complianceitems"
var esRequestMax = 1000000

type fieldResponse struct {
	Hostname []string `json:"target"`
}

func requestCompliance(eshost string) ([]string, error) {
	var ret []string
	fmt.Fprintf(os.Stdout, "Requesting compliance items...\n")

	conn := elastigo.NewConn()
	conn.Domain = eshost

	template := `{
		"size": %v,
		"fields": [ "target" ],
		"query": {
			"bool": {
				"must": [
				{
					"term": {
						"_type": "last_known_state"
					}
				}
				]
			}
		}
	}`
	tempbuf := fmt.Sprintf(template, esRequestMax)
	res, err := conn.Search(compIndex, "last_known_state", nil, tempbuf)
	if err != nil {
		return ret, err
	}
	for _, x := range res.Hits.Hits {
		var nfr fieldResponse
		err = json.Unmarshal(*x.Fields, &nfr)
		if err != nil {
			return ret, err
		}
		if len(nfr.Hostname) == 0 {
			continue
		}
		found := false
		for _, y := range ret {
			if y == nfr.Hostname[0] {
				found = true
				break
			}
		}
		if found {
			continue
		}
		ret = append(ret, nfr.Hostname[0])
	}
	fmt.Fprintf(os.Stdout, "Identified %v unique hosts in compliance items\n", len(ret))

	return ret, nil
}

func dbUpdateHost(hn string) error {
	_, err := dbconn.Exec(`INSERT INTO host
		(hostname, comment, dynamic, dynamic_added, dynamic_confidence, lastused)
		SELECT $1, 'compliance importer', TRUE, now() AT TIME ZONE 'utc',
		80, now() AT TIME ZONE 'utc'
		WHERE NOT EXISTS (
			SELECT 1 FROM host WHERE lower(hostname) = lower($2)
		)`, hn, hn)
	if err != nil {
		return err
	}
	_, err = dbconn.Exec(`UPDATE host
		SET lastused = now() AT TIME ZONE 'utc'
		WHERE lower(hostname) = lower($1)`, hn)
	if err != nil {
		return err
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
	flag.StringVar(&eshost, "e", "", "es hostname")
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
	hosts, err := requestCompliance(eshost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for _, x := range hosts {
		err = dbUpdateHost(x)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
}
