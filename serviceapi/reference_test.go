// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"

	"testing"
)

func TestGetReference(t *testing.T) {
	op := opContext{}
	op.newContext(dbconn, false, "127.0.0.1")

	rra, err := getRRA(op, 4)
	if err != nil {
		t.Fatalf("getRRA: %v", err)
	}
	if rra.Name != "Reference service" {
		t.Fatalf("getRRA: unexpected service name")
	}
	if rra.ConfiRepImpact != "high" {
		t.Fatalf("getRRA: unexpected impact for reference service attribute")
	}
	if rra.DefData != "confidential restricted" {
		t.Fatalf("getRRA: unexpected data classification for reference service attribute")
	}

	risk, err := riskForRRA(op, false, 4)
	if err != nil {
		t.Fatalf("riskForRRA: %v", err)
	}
	_, err = json.Marshal(risk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Validate some of the fields in the reference risk document
	if risk.RRA.Name != "Reference service" {
		t.Fatalf("riskForRRA: unexpected service name")
	}

	// We should have one asset group, named "reference"
	if len(risk.RRA.Groups) != 1 {
		t.Fatalf("riskForRRA: unexpected number of asset groups")
	}
	if risk.RRA.Groups[0].Name != "reference" {
		t.Fatalf("riskForRRA: incorrect asset group name")
	}

	// We should have two assets in this group
	if len(risk.RRA.Groups[0].Assets) != 2 {
		t.Fatalf("riskForRRA: incorrect number of assets in asset group")
	}

	// We should have 5 scenarios here for the indicators provided and the derived RRA probability
	if len(risk.Scenarios) != 5 {
		t.Fatalf("riskForRRA: incorrect number of scenarios")
	}
}
