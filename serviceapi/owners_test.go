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

func TestServiceHostOwner(t *testing.T) {
	client := http.Client{}

	// Tests first asset in service2
	rr, err := client.Get(testserv.URL + "/api/v1/owner/hostname?hostname=anothertesthost.mozilla.com")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("host get owner response code %v", rr.StatusCode)
	}
	buf, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll: %v", err)
	}
	rr.Body.Close()
	var owner slib.Owner
	err = json.Unmarshal(buf, &owner)
	if err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if owner.Operator != "operator" {
		t.Fatalf("host get owner had unexpected operator")
	}
	if owner.Team != "anothertestservice" {
		t.Fatalf("host get owner had unexpected team")
	}
	if owner.TriageKey != "operator-anothertestservice" {
		t.Fatalf("host get owner had unexpected triage key")
	}
}

func TestServiceHostOwnerUnknown(t *testing.T) {
	client := http.Client{}

	// Tests second asset in service2
	rr, err := client.Get(testserv.URL + "/api/v1/owner/hostname?hostname=noowner.mozilla.com")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("host get owner response code %v", rr.StatusCode)
	}
	buf, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll: %v", err)
	}
	rr.Body.Close()
	var owner slib.Owner
	err = json.Unmarshal(buf, &owner)
	if err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if owner.Operator != "unset" {
		t.Fatalf("host get owner had unexpected operator")
	}
	if owner.Team != "unset" {
		t.Fatalf("host get owner had unexpected team")
	}
	if owner.TriageKey != "unset-unset" {
		t.Fatalf("host get owner had unexpected triage key")
	}
}

func TestServiceHostOwnerNoExist(t *testing.T) {
	client := http.Client{}

	// Tests second asset in service2
	rr, err := client.Get(testserv.URL + "/api/v1/owner/hostname?hostname=NOEXIST")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusNotFound {
		t.Fatalf("host get owner response code %v", rr.StatusCode)
	}
	rr.Body.Close()
}
