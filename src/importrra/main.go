// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

// Imports RRA information from the RRA index and stores it in the database,
// can also be used to update existing RRAs in the database if they have
// changed in the index
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

func (r *rra) validate() error {
	return r.Details.validate()
}

type rraDetails struct {
	Metadata rraMetadata `json:"metadata"`
	Risk     rraRisk     `json:"risk"`
	Data     rraData     `json:"data"`
}

func (r *rraDetails) validate() error {
	err := r.Metadata.validate()
	if err != nil {
		return err
	}
	err = r.Risk.validate(r.Metadata.Service)
	if err != nil {
		return err
	}
	err = r.Data.validate(r.Metadata.Service)
	if err != nil {
		return err
	}
	return nil
}

type rraMetadata struct {
	Service string `json:"service"`
}

func (r *rraMetadata) validate() error {
	if r.Service == "" {
		return fmt.Errorf("rra has no service name")
	}
	// Do some sanitization of the service name if neccessary
	r.Service = strings.Replace(r.Service, "\n", " ", -1)
	r.Service = strings.TrimSpace(r.Service)
	return nil
}

type rraData struct {
	Default string `json:"default"`
}

func (r *rraData) validate(s string) error {
	if r.Default == "" {
		return fmt.Errorf("rra has no default data classification")
	}
	// Sanitize the data classification
	// XXX This should likely be checked against a list of known valid
	// strings
	r.Default = strings.ToLower(r.Default)
	// Convert from some older classification values
	switch r.Default {
	case "internal":
		r.Default = "confidential internal"
	case "restricted":
		r.Default = "confidential restricted"
	case "secret":
		r.Default = "confidential secret"
	}
	return nil
}

type rraRisk struct {
	Confidentiality rraRiskAttr `json:"confidentiality"`
	Integrity       rraRiskAttr `json:"integrity"`
	Availability    rraRiskAttr `json:"availability"`
}

func (r *rraRisk) validate(s string) error {
	err := r.Confidentiality.validate(s)
	if err != nil {
		return err
	}
	err = r.Integrity.validate(s)
	if err != nil {
		return err
	}
	err = r.Availability.validate(s)
	if err != nil {
		return err
	}
	return nil
}

type rraRiskAttr struct {
	Reputation   rraMeasure `json:"reputation"`
	Finances     rraMeasure `json:"finances"`
	Productivity rraMeasure `json:"productivity"`
}

func (r *rraRiskAttr) validate(s string) error {
	err := r.Reputation.validate(s)
	if err != nil {
		return err
	}
	err = r.Finances.validate(s)
	if err != nil {
		return err
	}
	err = r.Productivity.validate(s)
	if err != nil {
		return err
	}
	return nil
}

type rraMeasure struct {
	Impact      string `json:"impact"`
	Probability string `json:"probability"`
}

func (r *rraMeasure) validate(s string) (err error) {
	r.Impact, err = verifyLabel(r.Impact)
	if err != nil {
		return err
	}
	// XXX If the probability value is unset, just default it to unknown
	// here and continue. We can proceed without this value, if we at least
	// have the impact. Without this though certain calculation datapoints
	// may not be possible.
	if r.Probability == "" {
		r.Probability = "unknown"
		fmt.Fprintf(os.Stderr, "warning: default probability to unknown for \"%v\"\n", s)
	}
	r.Probability, err = verifyLabel(r.Probability)
	if err != nil {
		return err
	}
	return nil
}

var rraIndex = "rra"
var rraList []rra

// Verify and sanitize a risk impact label
func verifyLabel(l string) (ret string, err error) {
	if l == "" {
		err = fmt.Errorf("invalid zero length label")
		return
	}
	ret = strings.ToLower(l)
	if ret != "maximum" && ret != "high" && ret != "medium" &&
		ret != "low" && ret != "unknown" {
		err = fmt.Errorf("invalid label \"%v\"", ret)
		return
	}
	return
}

func requestRRAs(eshost string) error {
	fmt.Fprintf(os.Stdout, "Requesting RRA list...\n")

	conn := elastigo.NewConn()
	conn.Domain = eshost

	template := `{
		"from": %v,
		"size": 10,
		"sort": [
		{ "details.metadata.service": "asc" }
		],
		"query": {
			"bool": {
				"must": [
					{
					"term": {
						"category": "rra_data"
					}},
					{
					"range": {
						"utctimestamp": {
							"gt": "now-7d"
						}
					}}
				]
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
			err = nrra.validate()
			if err != nil {
				// If the RRA failed validation, it has some
				// sort of formatting issue, just log it and
				// continue; try to include the service name
				// if we can
				sname := "unknown service"
				if nrra.Details.Metadata.Service != "" {
					sname = nrra.Details.Metadata.Service
				}
				fmt.Fprintf(os.Stderr, "warning: skipping \"%v\", %v\n", sname, err)
				continue
			}
			rraList = append(rraList, nrra)
		}
	}
	fmt.Fprintf(os.Stdout, "Fetched %v RRAs\n", len(rraList))

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
		// Extract impact information.
		var (
			riskARI string
			riskARP string
			riskAPI string
			riskAPP string
			riskAFI string
			riskAFP string

			riskCRI string
			riskCRP string
			riskCPI string
			riskCPP string
			riskCFI string
			riskCFP string

			riskIRI string
			riskIRP string
			riskIPI string
			riskIPP string
			riskIFI string
			riskIFP string

			datadef string
		)
		riskARI = x.Details.Risk.Availability.Reputation.Impact
		riskARP = x.Details.Risk.Availability.Reputation.Probability
		riskAPI = x.Details.Risk.Availability.Productivity.Impact
		riskAPP = x.Details.Risk.Availability.Productivity.Probability
		riskAFI = x.Details.Risk.Availability.Finances.Impact
		riskAFP = x.Details.Risk.Availability.Finances.Probability

		riskCRI = x.Details.Risk.Confidentiality.Reputation.Impact
		riskCRP = x.Details.Risk.Confidentiality.Reputation.Probability
		riskCPI = x.Details.Risk.Confidentiality.Productivity.Impact
		riskCPP = x.Details.Risk.Confidentiality.Productivity.Probability
		riskCFI = x.Details.Risk.Confidentiality.Finances.Impact
		riskCFP = x.Details.Risk.Confidentiality.Finances.Probability

		riskIRI = x.Details.Risk.Integrity.Reputation.Impact
		riskIRP = x.Details.Risk.Integrity.Reputation.Probability
		riskIPI = x.Details.Risk.Integrity.Productivity.Impact
		riskIPP = x.Details.Risk.Integrity.Productivity.Probability
		riskIFI = x.Details.Risk.Integrity.Finances.Impact
		riskIFP = x.Details.Risk.Integrity.Finances.Probability

		datadef = x.Details.Data.Default

		fmt.Fprintf(os.Stdout, "RRA: %v\n", x.Details.Metadata.Service)
		_, err := dbconn.Exec(`INSERT INTO rra
			(service, ari, api, afi, cri, cpi, cfi, iri, ipi, ifi,
			arp, app, afp, crp, cpp, cfp, irp, ipp, ifp, datadefault,
			lastupdated)
			SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			now() AT TIME ZONE 'utc'
			WHERE NOT EXISTS (
				SELECT 1 FROM rra WHERE service = $21
			)`,
			x.Details.Metadata.Service, riskARI, riskAPI, riskAFI,
			riskCRI, riskCPI, riskCFI, riskIRI, riskIPI, riskIFI,
			riskARP, riskAPP, riskAFP, riskCRP, riskCPP, riskCFP,
			riskIRP, riskIPP, riskIFP, datadef, x.Details.Metadata.Service)
		if err != nil {
			return err
		}
		_, err = dbconn.Exec(`UPDATE rra
			SET
			ari = $1,
			api = $2,
			afi = $3,
			cri = $4,
			cpi = $5,
			cfi = $6,
			iri = $7,
			ipi = $8,
			ifi = $9,
			arp = $10,
			app = $11,
			afp = $12,
			crp = $13,
			cpp = $14,
			cfp = $15,
			irp = $16,
			ipp = $17,
			ifp = $18,
			datadefault = $19,
			lastupdated = now() AT TIME ZONE 'utc'
			WHERE service = $20`,
			riskARI, riskAPI, riskAFI,
			riskCRI, riskCPI, riskCFI, riskIRI, riskIPI, riskIFI,
			riskARP, riskAPP, riskAFP, riskCRP, riskCPP, riskCFP,
			riskIRP, riskIPP, riskIFP, datadef, x.Details.Metadata.Service)
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
