// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"strconv"
	"strings"
	"testing"
)

type resultSpec struct {
	Median string `json:"median"`
}

func TestRiskResults(t *testing.T) {
	dirlist, err := ioutil.ReadDir("./testdata")
	if err != nil {
		t.Fatalf("ioutil.ReadDir: %v", err)
	}
	for _, x := range dirlist {
		var spec resultSpec

		if !strings.HasPrefix(x.Name(), "service") {
			continue
		}
		specpath := path.Join("./testdata", x.Name(), "result.json")
		idstr := strings.TrimPrefix(x.Name(), "service")
		rraid, err := strconv.Atoi(idstr)
		if err != nil {
			t.Fatalf("strconv.Atoi: %v", err)
		}

		buf, err := ioutil.ReadFile(specpath)
		if err != nil {
			t.Fatalf("ioutil.ReadFile: %v", err)
		}
		err = json.Unmarshal(buf, &spec)
		if err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}

		op := opContext{}
		op.newContext(dbconn, false, "127.0.0.1")
		risk, err := riskForRRA(op, false, rraid)
		if err != nil {
			t.Fatalf("riskForRRA: %v", err)
		}

		if risk.Risk.MedianLabel != spec.Median {
			t.Fatalf("service %v risk median value incorrect", x.Name())
		}
	}
}
