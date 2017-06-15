// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	slib "github.com/mozilla/service-map/servicelib"
	"net/http"
)

func getTargetVulns(target string) (ret slib.Vuln, err error) {
	return ret, nil
}

func serviceGetVulnsTarget(rw http.ResponseWriter, req *http.Request) {
}
