// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Describes an RRA.
type RRAService struct {
	Name string `json:"name,omitempty"`
	ID   int    `json:"id,omitempty"`

	/* Attribute impact scores */
	AvailRepImpact string `json:"availability_reputation_impact,omitempty"`
	AvailPrdImpact string `json:"availability_productivity_impact,omitempty"`
	AvailFinImpact string `json:"availability_financial_impact,omitempty"`
	IntegRepImpact string `json:"integrity_reputation_impact,omitempty"`
	IntegPrdImpact string `json:"integrity_productivity_impact,omitempty"`
	IntegFinImpact string `json:"integrity_financial_impact,omitempty"`
	ConfiRepImpact string `json:"confidentiality_reputation_impact,omitempty"`
	ConfiPrdImpact string `json:"confidentiality_productivity_impact,omitempty"`
	ConfiFinImpact string `json:"confidentiality_financial_impact,omitempty"`

	/* Attribute probability scores */
	AvailRepProb string `json:"availability_reputation_probability,omitempty"`
	AvailPrdProb string `json:"availability_productivity_probability,omitempty"`
	AvailFinProb string `json:"availability_financial_probability,omitempty"`
	IntegRepProb string `json:"integrity_reputation_probability,omitempty"`
	IntegPrdProb string `json:"integrity_productivity_probability,omitempty"`
	IntegFinProb string `json:"integrity_financial_probability,omitempty"`
	ConfiRepProb string `json:"confidentiality_reputation_probability,omitempty"`
	ConfiPrdProb string `json:"confidentiality_productivity_probability,omitempty"`
	ConfiFinProb string `json:"confidentiality_financial_probability,omitempty"`

	DefData string `json:"default_data_classification,omitempty"`

	// Supporting system groups
	SupportGrps []SystemGroup `json:"supporting_system_groups,omitempty"`

	RawRRA json.RawMessage `json:"rra_details,omitempty"` // The raw RRA as described in ES
}

func (r *RRAService) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rra must have a name")
	}
	return nil
}

// Score values per impact label
const (
	ImpactUnknownValue = 0.0
	ImpactLowValue     = 1.0
	ImpactMediumValue  = 2.0
	ImpactHighValue    = 3.0
	ImpactMaxValue     = 4.0
)

// Describes calculated risk for a service, based on an RRA and known
// data points
type RRAServiceRisk struct {
	RRA RRAService `json:"rra"` // The RRA we are describing

	// Without a way to know which impact properties a given data point
	// affects (for example, confidentiality but not availability), we
	// just use the highest noted impact for the asset.
	//
	// This is derived from the information stored in the RRA
	HighestImpact     string `json:"highest_impact"`             // The highest impact score associated with the service
	HighestImpactProb string `json:"highest_impact_probability"` // Probability of highest impact

	RiskScore   float64         `json:"score"`            // The final risk score for the service
	WorstCase   float64         `json:"worst_case"`       // Worst case score given available data points
	NormalRisk  float64         `json:"normalized_score"` // Normalized risk score
	NormalLabel string          `json:"normalized_label"` // Normalized risk score label
	Datapoints  []RiskDatapoint `json:"datapoints"`       // Data points for risk calculation
}

func (r *RRAServiceRisk) Validate() error {
	err := r.RRA.Validate()
	if err != nil {
		return err
	}
	return nil
}

// Stores information used to support probability for risk calculation; this
// generally would be created using control information and is combined with the
// RRA impact scores to produce estimated service risk
type RiskDatapoint struct {
	Name     string  `json:"name"`     // Name describing the datapoint
	Weight   float64 `json:"weight"`   // Weight of the datapoint in calculation
	Score    float64 `json:"score"`    // The scored value for the datapoint
	Cap      float64 `json:"cap"`      // Value cap, 0.0 - 1.0, should default to 1.0
	NoData   bool    `json:"nodata"`   // True if no data exists for this datapoint
	Coverage string  `json:"coverage"` // The coverage of the calculation, should be none, partial, or complete
}

// Validates a RiskDatapoint for consistency
func (r *RiskDatapoint) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("datapoint must have a name")
	}
	if r.Weight == 0 {
		return fmt.Errorf("datapoint \"%v\" weight must not be zero", r.Name)
	}
	if r.Cap < 0 || r.Cap > 1.0 {
		return fmt.Errorf("datapoint \"%v\" cap must be from 0.0 to 1.0, not %v", r.Name, r.Cap)
	}
	if r.Coverage != "none" && r.Coverage != "partial" &&
		r.Coverage != "complete" && r.Coverage != "unknown" {
		return fmt.Errorf("datapoint \"%v\" coverage invalid \"%v\"", r.Name, r.Coverage)
	}
	return nil
}

// Convert an impact label into the numeric representation from 1 - 4 for
// that label
func ImpactValueFromLabel(l string) (float64, error) {
	switch l {
	case "maximum":
		return ImpactMaxValue, nil
	case "high":
		return ImpactHighValue, nil
	case "medium":
		return ImpactMediumValue, nil
	case "low":
		return ImpactLowValue, nil
	case "unknown":
		return ImpactUnknownValue, nil
	}
	return 0, fmt.Errorf("invalid impact label %v", l)
}

// Sanitize an impact label and verify it's a valid value
func SanitizeImpactLabel(l string) (ret string, err error) {
	if l == "" {
		err = fmt.Errorf("invalid zero length label")
		return
	}
	ret = strings.ToLower(l)
	if ret != "maximum" && ret != "high" && ret != "medium" &&
		ret != "low" && ret != "unknown" {
		err = fmt.Errorf("invalid impact label \"%v\"", ret)
	}
	return
}

// Covert an impact value from 1 - 4 to the string value for that label,
// note that does not handle decimal values in the floating point value
// and should only be used with 1.0, 2.0, 3.0, or 4.0
func ImpactLabelFromValue(v float64) (string, error) {
	switch v {
	case ImpactMaxValue:
		return "maximum", nil
	case ImpactHighValue:
		return "high", nil
	case ImpactMediumValue:
		return "medium", nil
	case ImpactLowValue:
		return "low", nil
	case ImpactUnknownValue:
		return "unknown", nil
	}
	return "", fmt.Errorf("invalid impact value %v", v)
}

// Given a normalize risk score from 0.0 - 100.0, convert that score into
// the string value that represents the risk
func NormalLabelFromValue(v float64) string {
	if v >= 75 {
		return "maximum"
	} else if v >= 50 {
		return "high"
	} else if v >= 25 {
		return "medium"
	}
	return "low"
}
