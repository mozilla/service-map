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
	"net/http"
)

// Process a new indicator request
func serviceIndicator(rw http.ResponseWriter, req *http.Request) {
	var (
		indicator slib.RawIndicator
		err       error
	)
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	decoder := json.NewDecoder(req.Body)
	err = decoder.Decode(&indicator)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "indicator document malformed", 400)
	}
	err = indicator.Validate()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "indicator document malformed", 400)
	}
}
