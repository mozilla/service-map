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

type Website struct {
	ID         int       `json:"id"`
	SysGroupID int       `json:"sysgroupid"`
	Website    string    `json:"hostname"`
	Comment    string    `json:"comment"`
	Dynamic    bool      `json:"dynamic"`
	LastUsed   time.Time `json:"lastused"`

	HTTPObs HTTPObsStatus `json:"http_observatory"`
}

type HTTPObsStatus struct {
	Coverage    bool   `json:"coverage"`
	Score       int    `json:"score"`
	Grade       string `json:"grade"`
	TestsFailed int    `json:"tests_failed"`
	TestsPassed int    `json:"tests_passed"`
	TestsTotal  int    `json:"tests_total"`
}
