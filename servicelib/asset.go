// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

import (
	"errors"
	"time"
)

// Asset describes an asset stored within serviceapi
//
// The asset can also include the list of most recent indicators for the asset. Note that
// the list includes the last indicator from a given event source, and it should not include
// all indicators seen over a time period (e.g., we should not include more than one indicator
// for any given event source)
type Asset struct {
	ID            int         `json:"id"`                         // Asset ID
	Type          string      `json:"asset_type,omitempty"`       // Asset type (e.g., hostname, website, etc)
	Name          string      `json:"asset_identifier,omitempty"` // Asset name
	Zone          string      `json:"zone,omitempty"`             // Asset zone
	AssetGroupID  int         `json:"asset_group_id,omitempty"`   // Group ID asset is in
	LastIndicator time.Time   `json:"last_indicator,omitempty"`   // Time last indicator was received for asset
	Owner         Owner       `json:"owner"`                      // Ownership details
	Indicators    []Indicator `json:"indicators"`                 // Most recent indicators for asset
}

// Validate ensures an Asset is formatted correctly
func (a *Asset) Validate() error {
	if a.Type == "" {
		return errors.New("asset type missing")
	}
	if a.Name == "" {
		return errors.New("asset name missing")
	}
	return nil
}
