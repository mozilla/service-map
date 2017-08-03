// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

import (
	"errors"
	"strings"
	"time"
)

// Indicator describes an indicator as it is internally stored by serviceapi, and
// indicators are associated with assets
type Indicator struct {
	ID          int         `json:"id"`
	EventSource string      `json:"event_source,omitempty"`
	Timestamp   time.Time   `json:"timestamp_utc"`
	Likelihood  string      `json:"likelihood_indicator"`
	Details     interface{} `json:"details,omitempty"`
}

// RawIndicator describes an indicator as would be submitted to serviceapi from an
// event publisher
type RawIndicator struct {
	Type        string      `json:"asset_type,omitempty"`
	Name        string      `json:"asset_identifier,omitempty"`
	Zone        string      `json:"zone,omitempty"`
	Description string      `json:"description,omitempty"`
	Timestamp   time.Time   `json:"timestamp_utc"`
	EventSource string      `json:"event_source_name,omitempty"`
	Likelihood  string      `json:"likelihood_indicator,omitempty"`
	Details     interface{} `json:"details,omitempty"`
}

// Validate ensures a RawIndicator is formatted correctly
func (i *RawIndicator) Validate() error {
	if i.Type == "" {
		return errors.New("indicator asset type missing")
	}
	if i.Name == "" {
		return errors.New("indicator asset name/identifier missing")
	}
	if i.EventSource == "" {
		return errors.New("indicator event source missing")
	}
	if i.Timestamp.IsZero() {
		return errors.New("indicator has invalid time stamp")
	}
	i.Likelihood = strings.ToLower(i.Likelihood)
	switch i.Likelihood {
	case "maximum":
	case "high":
	case "medium":
	case "low":
	case "unknown":
	default:
		return errors.New("indicator has invalid likelihood value")
	}
	return nil
}
