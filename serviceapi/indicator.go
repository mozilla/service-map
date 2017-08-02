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
	slib "github.com/mozilla/service-map/servicelib"
	"net/http"
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
	op.logf("adding new indicator for asset %v (%v)", asset.ID, indicator.EventSource)
	_, err = op.Exec(`INSERT INTO indicator
		(timestamp, event_source, likelihood_indicator, assetid, details)
		VALUES ($1, $2, $3, $4, $5)`,
		indicator.Timestamp, indicator.EventSource, indicator.Likelihood,
		asset.ID, string(detailsbuf))
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, "error processing indicator", 500)
		return
	}
}

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
	if ownid.Valid {
		ret.Owner, err = getOwner(op, int(ownid.Int64))
		if err != nil {
			return ret, err
		}
	}
	if triageoverride.Valid {
		ret.Owner.TriageKey = triageoverride.String
	}
	return
}

// Given a raw indicator, attempt to locate the relevant asset for the indicator
// in the database. If not found, add a new asset for the indicator.
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
