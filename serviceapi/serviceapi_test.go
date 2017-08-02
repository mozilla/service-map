// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	slib "github.com/mozilla/service-map/servicelib"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

var testserv *httptest.Server

func addTestBase(sroot string) error {
	client := http.Client{}

	// Add all valid RRAs
	dirlist, err := ioutil.ReadDir(path.Join(sroot, "rra"))
	if err != nil {
		return err
	}
	for _, f := range dirlist {
		fd, err := os.Open(path.Join(sroot, "rra", f.Name()))
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

	// Generate test indicators
	dirlist, err = ioutil.ReadDir(path.Join(sroot, "indicator"))
	if err != nil {
		return err
	}
	for _, f := range dirlist {
		// For each valid indicator, we will generate a series of indicators mutating
		// the timestamp
		fd, err := os.Open(path.Join(sroot, "indicator", f.Name()))
		if err != nil {
			return err
		}
		buf, err := ioutil.ReadAll(fd)
		if err != nil {
			return err
		}
		fd.Close()

		var ind slib.RawIndicator
		err = json.Unmarshal(buf, &ind)
		if err != nil {
			return err
		}

		stime := time.Now().Add(-1 * (time.Minute))
		ind.Timestamp = stime
		for i := 0; i < 10; i++ {
			ind.Timestamp = ind.Timestamp.Add(time.Second)
			sendbuf, err := json.Marshal(ind)
			if err != nil {
				return err
			}

			reader := bytes.NewReader(sendbuf)
			rr, err := client.Post(testserv.URL+"/api/v1/indicator", "application/json", reader)
			if err != nil {
				return err
			}
			if rr.StatusCode != http.StatusOK {
				return fmt.Errorf("indicator response code %v", rr.StatusCode)
			}
			rr.Body.Close()
		}
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

	dirlist, err := ioutil.ReadDir("./testdata")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	for _, f := range dirlist {
		if !strings.HasPrefix(f.Name(), "service") {
			continue
		}
		tdir := path.Join("./testdata", f.Name())
		err = addTestBase(tdir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}

	// Run the interlink rules prior to the other tests
	rules, err := interlinkLoadRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	err = interlinkRunRules(rules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}
