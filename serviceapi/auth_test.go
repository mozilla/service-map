// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"io/ioutil"
	"net/http"
	"testing"
)

func TestAPIAuthenticate(t *testing.T) {
	cfg.General.DisableAPIAuth = false

	client := http.Client{}

	// Attempt to get an RRA with no API key, which should fail
	rr, err := client.Get(testserv.URL + "/api/v1/rra/id?id=1")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request should have been unauthorized")
	}
	buf, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll: %v", err)
	}
	rr.Body.Close()
	if string(buf) != "unauthorized\n" {
		t.Fatalf("request body unexpected for unauthorized response")
	}

	// Add a new API key directly to the database, that doesn't match the key RE
	op := opContext{}
	op.newContext(dbconn, false, "127.0.0.1")
	_, err = op.Exec(`INSERT INTO apikey (name, hash) VALUES
		('testing', crypt('AAAAAAAA', gen_salt('bf', 8)))`)
	if err != nil {
		t.Fatalf("op.Exec: %v", err)
	}

	// Repeat the same request with no header, should still be unauthorized
	rr, err = client.Get(testserv.URL + "/api/v1/rra/id?id=1")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if rr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request should have been unauthorized")
	}
	buf, err = ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll: %v", err)
	}
	rr.Body.Close()
	if string(buf) != "unauthorized\n" {
		t.Fatalf("request body unexpected for unauthorized response")
	}

	// Repeat the request with the header value set, which should still be rejected
	// as the key does not match the header RE
	req, _ := http.NewRequest("GET", testserv.URL+"/api/v1/rra/id?id=1", nil)
	req.Header.Set("SERVICEAPIKEY", "AAAAAAAA")
	rr, err = client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	if rr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request should have been unauthorized")
	}
	buf, err = ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll: %v", err)
	}
	rr.Body.Close()
	if string(buf) != "unauthorized\n" {
		t.Fatalf("request body unexpected for unauthorized response")
	}

	// Add another key, which is a valid length
	_, err = op.Exec(`INSERT INTO apikey (name, hash) VALUES
		('testing2', crypt('AAAAAAAAAAAAAAAAAAAA', gen_salt('bf', 8)))`)
	if err != nil {
		t.Fatalf("op.Exec: %v", err)
	}

	// Repeat the request again, with a valid header
	req, _ = http.NewRequest("GET", testserv.URL+"/api/v1/rra/id?id=1", nil)
	req.Header.Set("SERVICEAPIKEY", "AAAAAAAAAAAAAAAAAAAA")
	rr, err = client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("request should have been OK")
	}
	rr.Body.Close()

	// Repeat the request with a bad key
	req, _ = http.NewRequest("GET", testserv.URL+"/api/v1/rra/id?id=1", nil)
	req.Header.Set("SERVICEAPIKEY", "xxxxxxxxxxxxxxxxxxxx")
	rr, err = client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	if rr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request should have been unauthorized")
	}
	rr.Body.Close()

	// Repeat the request with a zero length key
	req, _ = http.NewRequest("GET", testserv.URL+"/api/v1/rra/id?id=1", nil)
	req.Header.Set("SERVICEAPIKEY", "")
	rr, err = client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	if rr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request should have been unauthorized")
	}
	rr.Body.Close()

	cfg.General.DisableAPIAuth = true
}

func TestAPIAuthenticateDirect(t *testing.T) {
	var atab = []struct {
		hdr    string
		result bool
	}{
		{"AAAA", false},
		{"AAAAAAAAAAAAAAAAAAAA", true},
		{"AAAAAAAAAAAAAAAAAAA", false},
		{"AAAAAAAAAAAAAAAAAAAAA", false},
		{"", false},
		{" ", false},
		{")", false},
		{";", false},
		{"AAAAAAAAAAAAAAAAAAAA", true},
	}

	for _, x := range atab {
		var result bool
		result = true
		_, err := apiAuthenticate(x.hdr)
		if err != nil {
			result = false
		}
		if result != x.result {
			t.Fatalf("apiAuthenticate: unexpected result")
		}
	}
}
