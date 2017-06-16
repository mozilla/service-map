// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

type AssetGroup struct {
	Name   string  `json:"name,omitempty"`   // Group name
	ID     int     `json:"id,omitempty"`     // Group ID
	Assets []Asset `json:"assets,omitempty"` // Assets which are part of the group
}
