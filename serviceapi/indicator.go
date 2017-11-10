// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	slib "github.com/mozilla/service-map/servicelib"
	"net/http"
	"strings"
)

// serviceIndicator processes a new indicator being sent to serviceapi by
// an event publisher
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
		return
	}
	err = indicator.Validate()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "indicator document malformed", 400)
		return
	}

	asset, err := assetFromIndicator(op, indicator)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error processing indicator", 500)
		return
	}
	err = asset.Validate()
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error processing indicator", 500)
		return
	}
	detailsbuf, err := json.Marshal(indicator.Details)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error processing indicator", 500)
		return
	}
	err = insertIndicator(op, indicator, asset, detailsbuf)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error processing indicator", 500)
	}
	return
}

// serviceGetIndicators returns a JSON document that includes all the most recent indicators
// given specified criteria, currently limited to all recent indicators from a given event_source_name.
func serviceGetIndicators(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	req.ParseForm()
	eventSourceName := req.FormValue("event_source_name")
	if eventSourceName == "" {
		http.Error(rw, "event_source_name not specified", 400)
		return
	}

	inds, err := indicatorsFromEventSource(op, eventSourceName)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving indicators", 500)
		return
	}

	buf, err := json.Marshal(&inds)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error retrieving indicators", 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

func insertIndicator(op opContext, indicator slib.RawIndicator, asset slib.Asset, detailsbuf []byte) error {
	var err error
	op.logf("adding new indicator for asset %v (%v)", asset.ID, indicator.EventSource)
	_, err = op.Exec(`INSERT INTO indicator
		(timestamp, event_source, likelihood_indicator, assetid, details)
		VALUES ($1, $2, $3, $4, $5)`,
		indicator.Timestamp, indicator.EventSource, indicator.Likelihood,
		asset.ID, string(detailsbuf))
	return err
}

// getAsset returns asset ID aid from the database
func getAsset(op opContext, aid int) (ret slib.Asset, err error) {
	var (
		grpid, ownid   sql.NullInt64
		triageoverride sql.NullString
	)

	err = op.QueryRow(`SELECT assetid, assettype, name, zone,
		assetgroupid, ownerid, triageoverride, lastindicator
		FROM asset WHERE assetid = $1`, aid).Scan(&ret.ID,
		&ret.Type, &ret.Name, &ret.Zone,
		&grpid, &ownid, &triageoverride, &ret.LastIndicator)
	if err != nil {
		return
	}
	if grpid.Valid {
		ret.AssetGroupID = int(grpid.Int64)
	}
	ret.Owner.Operator = "unset"
	ret.Owner.Team = "unset"
	if ownid.Valid {
		ret.Owner, err = getOwner(op, int(ownid.Int64))
		if err != nil {
			return ret, err
		}
	}
	if triageoverride.Valid {
		ret.Owner.TriageKey = triageoverride.String
	} else {
		ret.Owner.TriageKey = ret.Owner.Operator + "-" + ret.Owner.Team
	}
	// Add the most recent indicators for the asset
	ret.Indicators, err = assetGetIndicators(op, ret)
	return
}

// getAssetByHost returns any hostname type assets from the database where the hostname
// matches hn
func getAssetHostname(op opContext, hn string) (ret []slib.Asset, err error) {
	hn = strings.ToLower(hn)
	rows, err := op.Query(`SELECT assetid FROM asset WHERE
		name = $1 AND assettype = 'hostname'`, hn)
	if err != nil {
		return
	}
	for rows.Next() {
		var aid int
		err = rows.Scan(&aid)
		if err != nil {
			rows.Close()
			return ret, err
		}
		newasset, err := getAsset(op, aid)
		if err != nil {
			rows.Close()
			return ret, err
		}
		ret = append(ret, newasset)
	}
	err = rows.Err()
	return
}

// indicatorsFromEventSource return all of the most recent indicators for a given event
// source name, the data is returned as a list of assets so we can capture the asset information
// associated with the indicator.
func indicatorsFromEventSource(op opContext, esn string) (ret []slib.Asset, err error) {
	var aidlist []int
	// First, get a unique list of relevant assets for the event_source_name
	rows, err := op.Query(`SELECT assetid FROM indicator WHERE event_source = $1 GROUP BY
		assetid`, esn)
	if err != nil {
		return
	}
	for rows.Next() {
		var aid int

		err = rows.Scan(&aid)
		if err != nil {
			rows.Close()
			return
		}
		aidlist = append(aidlist, aid)
	}
	err = rows.Err()
	if err != nil {
		return
	}

	// For each asset in our list, pull the full asset data and rewrite the indicator list
	// so it just includes the indicator we want
	for _, aid := range aidlist {
		tmpIndicators := make([]slib.Indicator, 0)
		a, err := getAsset(op, aid)
		if err != nil {
			return ret, err
		}
		tmpIndicators = a.Indicators
		a.Indicators = make([]slib.Indicator, 0)
		for _, i := range tmpIndicators {
			if i.EventSource != esn {
				continue
			}
			a.Indicators = append(a.Indicators, i)
		}
		ret = append(ret, a)
	}
	return
}

// assetGetIndicators returns a list of the most recent indicators for each distinct
// event source for an asset
func assetGetIndicators(op opContext, a slib.Asset) (ret []slib.Indicator, err error) {
	rows, err := op.Query(`SELECT x.timestamp, x.event_source, x.likelihood_indicator, x.details
		FROM indicator x INNER JOIN
		(SELECT event_source, MAX(timestamp) FROM indicator WHERE assetid = $1
		GROUP BY event_source) y
		ON x.event_source = y.event_source AND x.timestamp = y.max`, a.ID)
	if err != nil {
		return
	}
	for rows.Next() {
		var (
			newind  slib.Indicator
			details []byte
		)
		err = rows.Scan(&newind.Timestamp, &newind.EventSource, &newind.Likelihood,
			&details)
		if err != nil {
			rows.Close()
			return
		}
		err = json.Unmarshal(details, &newind.Details)
		if err != nil {
			rows.Close()
			return
		}
		ret = append(ret, newind)
	}
	err = rows.Err()
	return
}

// assetFromIndicator returns an asset given the information present in a RawIndicator, if
// an existing asset is present in the database this will be returned, otherwise a new asset
// is created and returned.
func assetFromIndicator(op opContext, indicator slib.RawIndicator) (ret slib.Asset, err error) {
	var aid int
	err = op.QueryRow(`SELECT assetid FROM asset
		WHERE assettype = $1 AND name = $2 AND zone = $3`,
		indicator.Type, indicator.Name, indicator.Zone).Scan(&aid)
	if err == nil {
		op.logf("making use of existing asset id %v", aid)
		return getAsset(op, aid)
	}
	if err != sql.ErrNoRows {
		return
	}
	// Otherwise, add the new asset and return it
	err = op.QueryRow(`INSERT INTO asset
		(assettype, name, zone, lastindicator)
		VALUES ($1, $2, $3, $4) RETURNING assetid`,
		indicator.Type, indicator.Name, indicator.Zone,
		indicator.Timestamp).Scan(&aid)
	if err != nil {
		return
	}
	op.logf("created new asset for %v/%v/%v (%v)", indicator.Name, indicator.Type,
		indicator.Zone, aid)
	return getAsset(op, aid)
}
