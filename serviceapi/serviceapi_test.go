// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
)

var testserv *httptest.Server

func addTestBase() error {
	client := http.Client{}

	// Add all valid RRAs
	dirlist, err := ioutil.ReadDir("./testdata/validrra")
	if err != nil {
		return err
	}
	for _, f := range dirlist {
		fd, err := os.Open(path.Join("./testdata/validrra", f.Name()))
		if err != nil {
			return err
		}
		rr, err := client.Post(testserv.URL+"/api/v1/rra/update", "application/json", fd)
		if err != nil {
			return err
		}
		if rr.StatusCode != http.StatusOK {
			return fmt.Errorf("rra update response code %v", rr.StatusCode)
		}
		rr.Body.Close()
		fd.Close()
	}

	return nil
}

func TestMain(m *testing.M) {
	logChan = make(chan string, 64)
	go func() {
		for {
			_ = <-logChan
		}
	}()

	cfg.General.Listen = "127.0.0.1:8080"
	cfg.General.RiskCacheEvery = "1m"
	cfg.General.DisableAPIAuth = true
	cfg.Database.Hostname = "127.0.0.1"
	cfg.Database.Database = "servicemap"
	cfg.Database.User = "dbadmin"
	cfg.Database.Password = "test"
	cfg.Interlink.RulePath = "./testdata/interlink.rules"
	cfg.Interlink.RunEvery = "10s"
	err := cfg.validate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	testserv = httptest.NewServer(muxRouter())
	defer testserv.Close()

	err = dbInit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	err = addTestBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}
