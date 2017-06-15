// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"
	"fmt"
	slib "github.com/mozilla/service-map/servicelib"
	"net/http"
)

func getTargetVulns(target string) (ret slib.Vuln, err error) {
	return ret, nil
}

func serviceGetVulnsTarget(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	target := req.FormValue("target")
	if target == "" {
		logf("must specify target for query")
		http.Error(rw, "must specify target for query", 500)
		return
	}

	vl, err := getTargetVulns(target)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	resp := slib.VulnsTargetResponse{}
	resp.Vulnerabilities = vl

	buf, err := json.Marshal(&resp)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}
