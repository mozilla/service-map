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
	"strings"
	"testing"
)

func TestGetRRA(t *testing.T) {
	op := opContext{}
	op.newContext(dbconn, false, "127.0.0.1")
	// Tests service1
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

	// Tests service1
	rr, err := client.Get(testserv.URL + "/api/v1/rra/id?id=1")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("rra get response code %v", rr.StatusCode)
	}
	buf, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll: %v", err)
	}
	rr.Body.Close()
	var rra slib.RRA
	err = json.Unmarshal(buf, &rra)
	if err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if rra.Name != "test service" {
		t.Fatalf("rra get rra had unexpected name")
	}
	if rra.ConfiRepImpact != "high" {
		t.Fatalf("rra get rra had unexpected service attribute value")
	}
	// The RRA should have one group associated with it
	if len(rra.Groups) != 1 {
		t.Fatalf("rra get rra associated with unexpected number of groups")
	}
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

func TestServiceGetRRARisk(t *testing.T) {
	client := http.Client{}

	// Tests service1
	rr, err := client.Get(testserv.URL + "/api/v1/rra/risk?id=1")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("rra get response code %v", rr.StatusCode)
	}
	buf, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll: %v", err)
	}
	rr.Body.Close()
	var r slib.Risk
	err = json.Unmarshal(buf, &r)
	if err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if r.Risk.MedianLabel != "medium" {
		t.Fatalf("rra get risk had unexpected median label value")
	}
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
	dirlist, err := ioutil.ReadDir("./testdata")
	if err != nil {
		t.Fatalf("ioutil.ReadDir: %v", err)
	}
	cnt := 0
	for _, x := range dirlist {
		if !strings.HasPrefix(x.Name(), "service") {
			continue
		}
		cnt++
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
	if cnt != len(rraresp.RRAs) {
		t.Fatalf("unexpected rra count from rras endpoint")
	}
}
