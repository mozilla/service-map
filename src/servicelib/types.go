// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

// Parameters used for a search request.
type SearchParams struct {
	Searches []Search `json:"search"` // Slice of searches to conduct for this request
}

// Describes an individual search.
type Search struct {
	Identifier string `json:"identifier,omitempty"` // A unique element identifier
	Host       string `json:"host,omitempty"`       // Host search criteria
}

// Describes a response to a search request.
type SearchResponse struct {
	SearchID string `json:"id"` // The ID of the search to fetch results
}

// The response to a search results request.
type SearchIDResponse struct {
	Results []SearchResult `json:"results"` // A slice of results for the search
}

type SearchResult struct {
	Identifier string  `json:"identifier"` // The unique element identifier used in the search request
	Service    Service `json:"service"`    // The service result information
}

// The response to a general service query.
type Service struct {
	Services    []RRAService `json:"services,omitempty"`    // Services linked from RRA table
	SystemGroup SystemGroup  `json:"systemgroup,omitempty"` // Database system group
	Found       bool         `json:"found"`                 // Results of search
}

// The response to a system group list request.
type SystemGroupsResponse struct {
	Results []SystemGroup `json:"results"`
}

// The response to a system group request.
type GetSystemGroupResponse struct {
	SystemGroup SystemGroup `json:"systemgroup"`
	Hosts       []string    `json:"hosts"`     // Hostnames statically linked to this group
	HostMatch   []string    `json:"hostmatch"` // Dynamic expression maps for hostnames
}

// The response to an RRA list request.
type RRAsResponse struct {
	Results []RRAService `json:"results"`
}

// The response to a match search request.
type SearchMatchResponse struct {
	Hosts []Host `json:"hosts"`
}
