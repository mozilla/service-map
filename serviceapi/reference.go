// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"
	"time"

	slib "github.com/mozilla/service-map/servicelib"
)

var referenceRRA = `
{
	"details": {
		"metadata": {
			"service": "Reference service"
		},
		"risk": {
			"confidentiality": {
				"reputation": {
					"impact": "HIGH",
					"probability": "HIGH"
				},
				"finances": {
					"impact": "HIGH",
					"probability": "HIGH"
				},
				"productivity": {
					"impact": "HIGH",
					"probability": "HIGH"
				}
			},
			"integrity": {
				"reputation": {
					"impact": "HIGH",
					"probability": "HIGH"
				},
				"finances": {
					"impact": "HIGH",
					"probability": "HIGH"
				},
				"productivity": {
					"impact": "HIGH",
					"probability": "HIGH"
				}
			},
			"availability": {
				"reputation": {
					"impact": "HIGH",
					"probability": "HIGH"
				},
				"finances": {
					"impact": "HIGH",
					"probability": "HIGH"
				},
				"productivity": {
					"impact": "HIGH",
					"probability": "HIGH"
				}
			}
		},
		"data": {
			"default": "confidential restricted"
		}
	},
	"lastmodified": "2017-08-02T14:25:47.511Z"
}
`

var platformVulnIndicator = `
{
	"asset_type": "hostname",
	"asset_identifier": "referencehost.reference.com",
	"zone": "reference",
	"timestamp_utc": "2017-08-02T14:25:47.511Z",
	"description": "scanapi vulnerability result",
	"event_source_name": "scanapi",
	"likelihood_indicator": "high",
	"details": {
		"coverage": true,
		"maximum": 0,
		"high": 1,
		"medium": 6,
		"low": 8
	}
}
`

var dastVulnIndicator = `
{
	"asset_type": "website",
	"asset_identifier": "referencewww.reference.com",
	"zone": "reference",
	"timestamp_utc": "2017-08-02T14:25:47.511Z",
	"description": "ZAP DAST scan",
	"event_source_name": "ZAP DAST scan",
	"likelihood_indicator": "medium",
	"details": [
		{
			"name": "Cookie No HttpOnly Flag",
			"site": "referencewww.reference.com",
			"likelihood_indicator": "low"
		},
		{
			"name": "Cross-Domain Javascript Source File Inclusion",
			"site": "referencewww.reference.com",
			"likelihood_indicator": "low"
		},
		{
			"name": "CSP scanner: script-src unsafe-inline",
			"site": "referencewww.reference.com",
			"likelihood_indicator": "medium"
		}
	]
}
`

var complianceIndicator = `
{
	"asset_type": "hostname",
	"asset_identifier": "referencehost.reference.com",
	"zone": "reference",
	"timestamp_utc": "2017-08-02T14:25:47.511Z",
	"description": "MIG compliance",
	"event_source_name": "MIG compliance",
	"likelihood_indicator": "medium",
	"details": [
		{
			"name": "syslowaudit1",
			"impact": "low",
			"compliance": false
		},
		{
			"name": "syshighremote1",
			"impact": "high",
			"compliance": true
		},
		{
			"name": "sysmediumconfig1",
			"impact": "medium",
			"compliance": false 
		}
	]
}
`

var observatoryIndicator = `
{
	"asset_type": "website",
	"asset_identifier": "referencewww.reference.com",
	"zone": "reference",
	"timestamp_utc": "2017-08-02T14:25:47.511Z",
	"description": "Mozilla Observatory scan",
	"event_source_name": "Mozilla Observatory",
	"likelihood_indicator": "medium",
	"details": {
		"grade": "F",
		"tests": [
			{
				"name": "Content security policy",
				"pass": false
			},
			{
				"name": "Cookies",
				"pass": true
			},
			{
				"name": "HTTP Public Key Pinning",
				"pass": false
			},
			{
				"name": "X-Frame-Options",
				"pass": false
			},
			{
				"name": "Cross-origin Resource Sharing",
				"pass": true
			}
		]
	}
}
`

func referenceUpdateIndicators() error {
	var indicator slib.RawIndicator

	op := opContext{}
	op.newContext(dbconn, false, "reference")

	// Platform vulnerability reference
	err := json.Unmarshal([]byte(platformVulnIndicator), &indicator)
	if err != nil {
		return err
	}
	indicator.Timestamp = time.Now().UTC()
	asset, err := assetFromIndicator(op, indicator)
	if err != nil {
		return err
	}
	detailsbuf, err := json.Marshal(indicator.Details)
	if err != nil {
		return err
	}
	err = insertIndicator(op, indicator, asset, detailsbuf)
	if err != nil {
		return err
	}

	// DAST vulnerability reference
	err = json.Unmarshal([]byte(dastVulnIndicator), &indicator)
	if err != nil {
		return err
	}
	indicator.Timestamp = time.Now().UTC()
	asset, err = assetFromIndicator(op, indicator)
	if err != nil {
		return err
	}
	detailsbuf, err = json.Marshal(indicator.Details)
	if err != nil {
		return err
	}
	err = insertIndicator(op, indicator, asset, detailsbuf)
	if err != nil {
		return err
	}

	// Compliance reference
	err = json.Unmarshal([]byte(complianceIndicator), &indicator)
	if err != nil {
		return err
	}
	indicator.Timestamp = time.Now().UTC()
	asset, err = assetFromIndicator(op, indicator)
	if err != nil {
		return err
	}
	detailsbuf, err = json.Marshal(indicator.Details)
	if err != nil {
		return err
	}
	err = insertIndicator(op, indicator, asset, detailsbuf)
	if err != nil {
		return err
	}

	// Observatory reference
	err = json.Unmarshal([]byte(observatoryIndicator), &indicator)
	if err != nil {
		return err
	}
	indicator.Timestamp = time.Now().UTC()
	asset, err = assetFromIndicator(op, indicator)
	if err != nil {
		return err
	}
	detailsbuf, err = json.Marshal(indicator.Details)
	if err != nil {
		return err
	}
	err = insertIndicator(op, indicator, asset, detailsbuf)
	if err != nil {
		return err
	}

	return nil
}

func referenceService() error {
	err := referenceUpdateRRA()
	if err != nil {
		return err
	}
	err = referenceUpdateIndicators()
	if err != nil {
		return err
	}
	return nil
}

func referenceUpdateRRA() error {
	var jsonrra slib.RawRRA

	op := opContext{}
	op.newContext(dbconn, false, "reference")

	err := json.Unmarshal([]byte(referenceRRA), &jsonrra)
	if err != nil {
		return err
	}
	err = jsonrra.Validate()
	if err != nil {
		return err
	}
	rra := jsonrra.ToRRA()
	err = insertRRA(op, rra, []byte(referenceRRA))
	rra.LastUpdated = time.Now().UTC()
	return err
}

func referenceUpdate() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in reference update routine: %v", e)
		}
	}()

	err := referenceService()
	if err != nil {
		panic(err)
	}
}
