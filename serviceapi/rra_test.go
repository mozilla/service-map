// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"
	slib "github.com/mozilla/service-map/servicelib"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestGetRRA(t *testing.T) {
	op := opContext{}
	op.newContext(dbconn, false, "127.0.0.1")
	rra, err := getRRA(op, 1)
	if err != nil {
		t.Fatalf("getRRA: %v", err)
	}
	if rra.Name != "test service" {
		t.Fatalf("getRRA: unexpected service name")
	}
	if rra.ConfiRepImpact != "high" {
		t.Fatalf("getRRA: unexpected impact for test service attribute")
	}
}

func TestServiceGetRRA(t *testing.T) {
	client := http.Client{}

	rr, err := client.Get(testserv.URL + "/api/v1/rra/id?id=1")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("rra get response code %v", rr.StatusCode)
	}
	rr.Body.Close()
}

func TestServiceGetNonExistRRA(t *testing.T) {
	client := http.Client{}

	rr, err := client.Get(testserv.URL + "/api/v1/rra/id?id=999")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusNotFound {
		t.Fatalf("rra get response code %v", rr.StatusCode)
	}
	rr.Body.Close()
}

func TestServiceRRAs(t *testing.T) {
	client := http.Client{}

	rr, err := client.Get(testserv.URL + "/api/v1/rras")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("rras get response code %v", rr.StatusCode)
	}

	// The number of RRAs returned should correspond with the number of
	// valid test RRAs we have
	var rraresp slib.RRAsResponse
	dirlist, err := ioutil.ReadDir("./testdata/validrra")
	if err != nil {
		t.Fatalf("ioutil.ReadDir: %v", err)
	}
	buf, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll: %v", err)
	}
	rr.Body.Close()
	err = json.Unmarshal(buf, &rraresp)
	if err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(dirlist) != len(rraresp.RRAs) {
		t.Fatalf("unexpected rra count from rras endpoint")
	}
}
