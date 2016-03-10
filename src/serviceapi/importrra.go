// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

// Deals with importing RRA data from the RRA index in MozDef, sanitizing
// the incoming data and storing it in the database.

import (
	"encoding/json"
	"fmt"
	elastigo "github.com/mattbaird/elastigo/lib"
	slib "servicelib"
	"strings"
)

// Defines a structure used to parse the fields from an RRA document that we
// want to normalize and store in the database. This doesn't describe all the
// fields in the RRA document.
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
	// strings, and we just reject importing an RRA that has a data
	// classification value we don't know about.
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
	r.Impact, err = slib.SanitizeImpactLabel(r.Impact)
	if err != nil {
		return err
	}
	// XXX If the probability value is unset, just default it to unknown
	// here and continue. We can proceed without this value, if we at least
	// have the impact. Without this though certain calculation datapoints
	// may not be possible.
	if r.Probability == "" {
		r.Probability = "unknown"
		logf("warning in rra import routine: defaulting probability to unknown for \"%v\"", s)
	}
	r.Probability, err = slib.SanitizeImpactLabel(r.Probability)
	if err != nil {
		return err
	}
	return nil
}

// requestRRAs will return a slice of rraESData types, this includes the raw RRA
// JSON itself, and an rra type including parsed out elements of the JSON we
// want to store in the database
type rraESData struct {
	rra rra
	raw json.RawMessage
}

func requestRRAs() (ret []rraESData, err error) {
	logf("importrra: refreshing rras")

	conn := elastigo.NewConn()
	defer conn.Close()
	conn.Domain = cfg.RRA.ESHost

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
		res, err := conn.Search(cfg.RRA.Index, "rra_state", nil, tempbuf)
		if err != nil {
			return ret, err
		}
		if res.Hits.Len() == 0 {
			break
		}
		for _, x := range res.Hits.Hits {
			var nrra rraESData
			err = json.Unmarshal(*x.Source, &nrra.rra)
			if err != nil {
				return ret, err
			}
			// Also store the entire message as a RawMessage, temporary
			// storage so we can place the entire RRA document in a
			// JSON column in the database.
			err = json.Unmarshal(*x.Source, &nrra.raw)
			if err != nil {
				return ret, err
			}
			err = nrra.rra.validate()
			if err != nil {
				// If the RRA failed validation, it has some
				// sort of formatting issue, just log it and
				// continue; try to include the service name
				// if we can
				sname := "unknown service"
				if nrra.rra.Details.Metadata.Service != "" {
					sname = nrra.rra.Details.Metadata.Service
				}
				logf("warning in rra import routine: skipping \"%v\", %v", sname, err)
				continue
			}
			ret = append(ret, nrra)
		}
	}
	logf("importrra: fetched %v rras", len(ret))

	return
}

func dbUpdateRRAs(rraList []rraESData) error {
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
		riskARI = x.rra.Details.Risk.Availability.Reputation.Impact
		riskARP = x.rra.Details.Risk.Availability.Reputation.Probability
		riskAPI = x.rra.Details.Risk.Availability.Productivity.Impact
		riskAPP = x.rra.Details.Risk.Availability.Productivity.Probability
		riskAFI = x.rra.Details.Risk.Availability.Finances.Impact
		riskAFP = x.rra.Details.Risk.Availability.Finances.Probability

		riskCRI = x.rra.Details.Risk.Confidentiality.Reputation.Impact
		riskCRP = x.rra.Details.Risk.Confidentiality.Reputation.Probability
		riskCPI = x.rra.Details.Risk.Confidentiality.Productivity.Impact
		riskCPP = x.rra.Details.Risk.Confidentiality.Productivity.Probability
		riskCFI = x.rra.Details.Risk.Confidentiality.Finances.Impact
		riskCFP = x.rra.Details.Risk.Confidentiality.Finances.Probability

		riskIRI = x.rra.Details.Risk.Integrity.Reputation.Impact
		riskIRP = x.rra.Details.Risk.Integrity.Reputation.Probability
		riskIPI = x.rra.Details.Risk.Integrity.Productivity.Impact
		riskIPP = x.rra.Details.Risk.Integrity.Productivity.Probability
		riskIFI = x.rra.Details.Risk.Integrity.Finances.Impact
		riskIFP = x.rra.Details.Risk.Integrity.Finances.Probability

		datadef = x.rra.Details.Data.Default

		buf, err := json.Marshal(&x.raw)
		if err != nil {
			return err
		}

		_, err = dbconn.Exec(`INSERT INTO rra
			(service, ari, api, afi, cri, cpi, cfi, iri, ipi, ifi,
			arp, app, afp, crp, cpp, cfp, irp, ipp, ifp, datadefault,
			lastupdated, raw)
			SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			now() AT TIME ZONE 'utc', $21
			WHERE NOT EXISTS (
				SELECT 1 FROM rra WHERE service = $22
			)`,
			x.rra.Details.Metadata.Service, riskARI, riskAPI, riskAFI,
			riskCRI, riskCPI, riskCFI, riskIRI, riskIPI, riskIFI,
			riskARP, riskAPP, riskAFP, riskCRP, riskCPP, riskCFP,
			riskIRP, riskIPP, riskIFP, datadef, buf, x.rra.Details.Metadata.Service)
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
			lastupdated = now() AT TIME ZONE 'utc',
			raw = $20
			WHERE service = $21`,
			riskARI, riskAPI, riskAFI,
			riskCRI, riskCPI, riskCFI, riskIRI, riskIPI, riskIFI,
			riskARP, riskAPP, riskAFP, riskCRP, riskCPP, riskCFP,
			riskIRP, riskIPP, riskIFP, datadef, buf, x.rra.Details.Metadata.Service)
		if err != nil {
			return err
		}
	}
	return nil
}

// Entry point for RRA import routine
func importRRA() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in rra import routine: %v", e)
		}
	}()
	rralist, err := requestRRAs()
	if err != nil {
		panic(err)
	}
	err = dbUpdateRRAs(rralist)
	if err != nil {
		panic(err)
	}
}
