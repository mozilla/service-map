// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

import (
	"time"
)

type Host struct {
	ID                 int       `json:"id"`
	SysGroupID         int       `json:"sysgroupid"`
	Hostname           string    `json:"hostname"`
	Comment            string    `json:"comment"`
	Dynamic            bool      `json:"dynamic"`
	DynamicLastUpdated time.Time `json:"dynamic_lastupdated"`
}

type HostMatch struct {
	ID         int    `json:"id"`
	SysGroupID int    `json:"sysgroupid"`
	Expression string `json:"expression"`
	Comment    string `json:"comment"`
}
