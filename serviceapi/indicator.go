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

// Process a new indicator request
func serviceIndicator(rw http.ResponseWriter, req *http.Request) {
	req.ParseMultipartForm(10000000)

	val := req.FormValue("params")
	if val == "" {
		logf("no indicator criteria specified")
		http.Error(rw, "no indicator criteria specified", 500)
		return
	}
	var params slib.IndicatorParams
	err := json.Unmarshal([]byte(val), &params)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	for _, x := range params.Indicators {
		if x.Host == "" {
			continue
		}
		err = updateDynamicHost(op, x.Host, "indicator request", 90)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
		err = processIndicator(op, x)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
	}

	ir := slib.IndicatorResponse{OK: true}
	buf, err := json.Marshal(&ir)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprint(rw, string(buf))
}

// Validate an indicator and update the database
func processIndicator(op opContext, ind slib.Indicator) (err error) {
	// Verify it's a class we expect, currently only vuln
	if ind.Class == "vuln" {
		_, err = op.Exec(`INSERT INTO vulnstatus
		(timestamp, assetid, checktype, status)
		VALUES (now(),
		(SELECT assetid FROM asset WHERE
		lower(hostname) = lower($1) AND
		assettype = 'host'),
		$2, $3)`, ind.Host, ind.CheckType, ind.Status)
		if err != nil {
			return err
		}
		return nil
	} else if ind.Class == "mig" {
		ebuf, err := json.Marshal(&ind.MIG.Environment)
		if err != nil {
			return err
		}
		tbuf, err := json.Marshal(&ind.MIG.Tags)
		if err != nil {
			return err
		}
		_, err = op.Exec(`INSERT INTO migstatus
		(timestamp, assetid, version, tags, env)
		VALUES (now(),
		(SELECT assetid FROM asset WHERE
		lower(hostname) = lower($1) AND
		assettype = 'host'),
		$2, $3, $4)`, ind.MIG.MIGHostname, ind.MIG.MIGVersion,
			string(tbuf), string(ebuf))
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("unknown indicator class")
}
