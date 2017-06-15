// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

// Describes an asset
type Asset struct {
	ID   int    `json:"id"`                         // Asset ID
	Type string `json:"asset_type,omitempty"`       // Asset type (e.g., hostname, website, etc)
	Name string `json:"asset_identifier,omitempty"` // Asset name
	Zone string `json:"zone,omitempty"`             // Asset zone
}
