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
	ID         int       `json:"id"`
	SysGroupID int       `json:"sysgroupid"`
	Hostname   string    `json:"hostname"`
	Comment    string    `json:"comment"`
	Dynamic    bool      `json:"dynamic"`
	LastUsed   time.Time `json:"lastused"`

	CompStatus ComplianceStatus `json:"compliance"`
}

type HostMatch struct {
	ID         int    `json:"id"`
	SysGroupID int    `json:"sysgroupid"`
	Expression string `json:"expression"`
	Comment    string `json:"comment"`
}

type ComplianceStatus struct {
	HighFail   int `json:"highfail"`
	HighPass   int `json:"highpass"`
	MediumFail int `json:"mediumfail"`
	MediumPass int `json:"mediumpass"`
	LowFail    int `json:"lowfail"`
	LowPass    int `json:"lowpass"`
}

func (c *ComplianceStatus) Reset() {
	c.HighFail = 0
	c.HighPass = 0
	c.MediumFail = 0
	c.MediumPass = 0
	c.LowFail = 0
	c.LowPass = 0
}
