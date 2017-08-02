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
}
