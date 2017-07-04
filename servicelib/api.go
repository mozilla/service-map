// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

// The response to an asset group list request
type AssetGroupsResponse struct {
	Groups []AssetGroup `json:"asset_groups"`
}

// The response to an RRA list request
type RRAsResponse struct {
	RRAs []RRA `json:"rras"`
}

// The response to a risks request; risk for all RRAs
type RisksResponse struct {
	Risks []Risk `json:"risks"`
}
