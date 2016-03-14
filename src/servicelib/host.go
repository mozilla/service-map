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

	CompStatus ComplianceStatus    `json:"compliance"`
	VulnStatus VulnerabilityStatus `json:"vulnerabilities"`
}

type VulnerabilityStatus struct {
	Maximum int `json:"maximum"`
	High    int `json:"high"`
	Medium  int `json:"medium"`
	Low     int `json:"low"`
}

func (v *VulnerabilityStatus) Reset() {
	v.Maximum = 0
	v.High = 0
	v.Medium = 0
	v.Low = 0
}

type ComplianceStatus struct {
	HighFail   int `json:"highfail"`
	HighPass   int `json:"highpass"`
	MediumFail int `json:"mediumfail"`
	MediumPass int `json:"mediumpass"`
	LowFail    int `json:"lowfail"`
	LowPass    int `json:"lowpass"`

	Details []ComplianceDetails `json:"details"`
}

type ComplianceDetails struct {
	CheckRef  string    `json:"checkref"`
	Status    bool      `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

func (c *ComplianceStatus) Reset() {
	c.HighFail = 0
	c.HighPass = 0
	c.MediumFail = 0
	c.MediumPass = 0
	c.LowFail = 0
	c.LowPass = 0
	c.Details = make([]ComplianceDetails, 0)
}
