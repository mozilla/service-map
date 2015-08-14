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
	"strings"
)

var dbconn *sql.DB

type rra struct {
	Details rraDetails `json:"details"`
}

func (r *rra) sanitize() error {
	r.Details.Metadata.Service = strings.Replace(r.Details.Metadata.Service, "\n", " ", -1)
	return nil
}

type rraDetails struct {
	Metadata rraMetadata `json:"metadata"`
}

type rraMetadata struct {
	Service string `json:"service"`
}

var rraIndex = "rra"
var rraList []rra

func requestRRAs(eshost string) error {
	fmt.Fprintf(os.Stdout, "Requesting RRA list...\n")

	conn := elastigo.NewConn()
	conn.Domain = eshost

	template := `{
		"from": %v,
		"size": 10,
		"query": {
			"term": {
				"category": "rra_data"
			}
		}
	}`
	for i := 0; ; i += 10 {
		tempbuf := fmt.Sprintf(template, i)
		res, err := conn.Search(rraIndex, "rra_state", nil, tempbuf)
		if err != nil {
			return err
		}
		if res.Hits.Len() == 0 {
			break
		}
		for _, x := range res.Hits.Hits {
			var nrra rra
			err = json.Unmarshal(*x.Source, &nrra)
			if err != nil {
				return err
			}
			err = nrra.sanitize()
			if err != nil {
				return err
			}
			rraList = append(rraList, nrra)
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

func dbUpdateRRAs() error {
	for _, x := range rraList {
		_, err := dbconn.Exec(`INSERT INTO rra (service)
			SELECT $1 WHERE NOT EXISTS (
				SELECT rraid FROM rra WHERE service = $2
			)`, x.Details.Metadata.Service, x.Details.Metadata.Service)
		if err != nil {
			return err
		}
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
	err = requestRRAs(eshost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	err = dbUpdateRRAs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
