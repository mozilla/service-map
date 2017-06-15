// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

// Describes the owner of an asset
type Owner struct {
	Operator  string `json:"operator,omitempty"`  // The operator (e.g., group)
	Team      string `json:"team,omitempty"`      // Team (e.g., team within the group)
	TriageKey string `json:"triagekey,omitempty"` // Triage key, used for integrated escalation tools
}
