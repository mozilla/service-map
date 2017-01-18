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

// Describes vulnerability events that are stored in MozDef

type Vuln struct {
	Description        string     `json:"description"`
	UTCTimestamp       time.Time  `json:"utctimestamp"`
	SourceName         string     `json:"sourcename"`
	CredentialedChecks bool       `json:"credentialed_checks"`
	Asset              VulnAsset  `json:"asset"`
	Vulns              []VulnVuln `json:"vulnerabilities"`
}

type VulnAsset struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ipaddress"`
	OS        string `json:"os"`
}

type VulnVuln struct {
	CVSS string `json:"cvss"`
	Risk string `json:"risk"`
	Name string `json:"name"`
	CVE  string `json:"cve"`
}
