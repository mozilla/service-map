// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

// Search types and various encapsulation used in certain API responses

import (
	"github.com/jvehent/gozdef"
)

// Parameters used for a search request.
type SearchParams struct {
	Searches []Search `json:"search"` // Slice of searches to conduct for this request
}

// Describes an individual search.
type Search struct {
	Identifier string `json:"identifier,omitempty"` // A unique element identifier
	Host       string `json:"host,omitempty"`       // Host search criteria
	Confidence int    `json:"confidence,omitempty"` // Reporter confidence
}

// Describes a response to a search request.
type SearchResponse struct {
	SearchID string `json:"id"` // The ID of the search to fetch results
}

// The response to a search results request.
type SearchIDResponse struct {
	Results []SearchResult `json:"results"` // A slice of results for the search
}

// An individual search result.
type SearchResult struct {
	Identifier string  `json:"identifier"` // Search request element identifier (from Search)
	Service    Service `json:"service"`    // The service result information
}

// Parameters to an indicator request
type IndicatorParams struct {
	Indicators []Indicator `json:"indicators"` // Slice of indicators to process
}

// Describes indicator information
type Indicator struct {
	// Common attributes amongst all classes
	Host string `json:"host,omitempty"` // Hostname of system

	Class string `json:"class"` // Indicator class

	// Used for "vuln" class indicators
	CheckType string `json:"checktype"`
	Status    bool   `json:"status"`

	// Used for "migagent" class indicators
	MIG IndicatorMIG `json:"mig"`
}

type IndicatorMIG struct {
	MIGHostname string      `json:"hostname"`
	MIGVersion  string      `json:"version"`
	Tags        interface{} `json:"tags"`
	Environment interface{} `json:"environment"`
}

// The response to an indicator request
type IndicatorResponse struct {
	OK bool `json:"ok"`
}

type RRAUpdateResponse struct {
	OK bool `json:"ok"`
}

// The response to a general service query.
type Service struct {
	Services    []RRAService `json:"services,omitempty"`    // Services linked from RRA table
	SystemGroup SystemGroup  `json:"systemgroup,omitempty"` // Database system group
	Owner       Owner        `json:"owner,omitempty"`       // Ownership details
	Found       bool         `json:"found"`                 // Results of search
}

// The response to a system group list request.
type SystemGroupsResponse struct {
	Results []SystemGroup `json:"results"`
}

// The response to an RRA list request.
type RRAsResponse struct {
	Results []RRAService `json:"results"`
}

// The response to a match search request.
type SearchMatchResponse struct {
	Hosts []Host `json:"hosts"`
}

// Response to vulnerabilities request for a target
type VulnsTargetResponse struct {
	Vulnerabilities []gozdef.VulnEvent `json:"vulnerabilities"`
}

// Response to /risks request, includes all known RRAs
type RisksResponse struct {
	Risks []RRAServiceRisk `json:"risks"`
}
