// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"testing"
)

func TestGetAsset(t *testing.T) {
	op := opContext{}
	op.newContext(dbconn, false, "127.0.0.1")
	// Tests the first asset in service1
	a, err := getAsset(op, 1)
	if err != nil {
		t.Fatalf("getAsset: %v", err)
	}
	if a.Name != "testhost1.mozilla.com" {
		t.Fatalf("getAsset: unexpected asset name")
	}
	if a.Type != "hostname" {
		t.Fatalf("getAsset: unexpected asset type")
	}
	if a.AssetGroupID != 1 {
		t.Fatalf("getAsset: unexpected asset group id")
	}
	if a.Owner.Operator != "operator" {
		t.Fatalf("getAsset: unexpected asset operator")
	}
	if a.Owner.Team != "testservice" {
		t.Fatalf("getAsset: unexpected asset team")
	}
	if a.Owner.TriageKey != "operator-testservice" {
		t.Fatalf("getAsset: unexpected asset triage key")
	}
}

func TestGetAssetHostname(t *testing.T) {
	op := opContext{}
	op.newContext(dbconn, false, "127.0.0.1")
	// Tests the first asset in service1
	alist, err := getAssetHostname(op, "testhost1.mozilla.com")
	if err != nil {
		t.Fatalf("getAssetHostname: %v", err)
	}
	if len(alist) != 1 {
		t.Fatalf("getAssetHostname: unexpected number of assets returned")
	}
	a := alist[0]
	if a.Name != "testhost1.mozilla.com" {
		t.Fatalf("getAsset: unexpected asset name")
	}
	if a.Type != "hostname" {
		t.Fatalf("getAsset: unexpected asset type")
	}
	if a.AssetGroupID != 1 {
		t.Fatalf("getAsset: unexpected asset group id")
	}
	if a.Owner.Operator != "operator" {
		t.Fatalf("getAsset: unexpected asset operator")
	}
	if a.Owner.Team != "testservice" {
		t.Fatalf("getAsset: unexpected asset team")
	}
	if a.Owner.TriageKey != "operator-testservice" {
		t.Fatalf("getAsset: unexpected asset triage key")
	}
}
