// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

// Types here provide support for legacy tools that base mapping on
// a list of expressions (vmintgr, etc); the types are returned using
// legacy endpoints

type VulnAuto struct {
	Match    string `json:"match"`
	Team     string `json:"team"`
	Operator string `json:"operator"`
	V2BKey   string `json:"v2bkey"`
}

type VulnAutoList struct {
	VulnAuto []VulnAuto `json:"vulnauto"`
}
