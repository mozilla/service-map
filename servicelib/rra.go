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
	"time"
)

// Describes an RRA.
type RRA struct {
	Name        string    `json:"name,omitempty"`
	ID          int       `json:"id,omitempty"`
	LastUpdated time.Time `json:"lastupdated,omitempty"`

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

	// Supporting asset groups
	SupportGrps []AssetGroup `json:"supporting_asset_groups,omitempty"`

	RawRRA json.RawMessage `json:"rra_details,omitempty"` // The raw RRA as described in ES
}

func (r *RRAService) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rra must have a name")
	}
	return nil
}

func (r *RRAService) HighestRiskReputation() (float64, float64) {
	// XXX Assumed values have been normalized here
	repavi, _ := ImpactValueFromLabel(r.AvailRepImpact)
	repavp, _ := ImpactValueFromLabel(r.AvailRepProb)
	repcfi, _ := ImpactValueFromLabel(r.ConfiRepImpact)
	repcfp, _ := ImpactValueFromLabel(r.ConfiRepProb)
	repiti, _ := ImpactValueFromLabel(r.IntegRepImpact)
	repitp, _ := ImpactValueFromLabel(r.IntegRepProb)
	rskav := repavi * repavp
	rskcf := repcfi * repcfp
	rskit := repiti * repitp
	var candr, candi, candp *float64
	candi = &repavi
	candp = &repavp
	candr = &rskav
	if rskcf > *candr {
		candi = &repcfi
		candp = &repcfp
		candr = &rskcf
	}
	if rskit > *candr {
		candi = &repiti
		candp = &repitp
		candr = &rskit
	}
	return *candi, *candp
}

func (r *RRAService) HighestRiskProductivity() (float64, float64) {
	// XXX Assumed values have been normalized here
	prdavi, _ := ImpactValueFromLabel(r.AvailPrdImpact)
	prdavp, _ := ImpactValueFromLabel(r.AvailPrdProb)
	prdcfi, _ := ImpactValueFromLabel(r.ConfiPrdImpact)
	prdcfp, _ := ImpactValueFromLabel(r.ConfiPrdProb)
	prditi, _ := ImpactValueFromLabel(r.IntegPrdImpact)
	prditp, _ := ImpactValueFromLabel(r.IntegPrdProb)
	rskav := prdavi * prdavp
	rskcf := prdcfi * prdcfp
	rskit := prditi * prditp
	var candr, candi, candp *float64
	candi = &prdavi
	candp = &prdavp
	candr = &rskav
	if rskcf > *candr {
		candi = &prdcfi
		candp = &prdcfp
		candr = &rskcf
	}
	if rskit > *candr {
		candi = &prditi
		candp = &prditp
		candr = &rskit
	}
	return *candi, *candp
}

func (r *RRAService) HighestRiskFinancial() (float64, float64) {
	// XXX Assumed values have been normalized here
	finavi, _ := ImpactValueFromLabel(r.AvailFinImpact)
	finavp, _ := ImpactValueFromLabel(r.AvailFinProb)
	fincfi, _ := ImpactValueFromLabel(r.ConfiFinImpact)
	fincfp, _ := ImpactValueFromLabel(r.ConfiFinProb)
	finiti, _ := ImpactValueFromLabel(r.IntegFinImpact)
	finitp, _ := ImpactValueFromLabel(r.IntegFinProb)
	rskav := finavi * finavp
	rskcf := fincfi * fincfp
	rskit := finiti * finitp
	var candr, candi, candp *float64
	candi = &finavi
	candp = &finavp
	candr = &rskav
	if rskcf > *candr {
		candi = &fincfi
		candp = &fincfp
		candr = &rskcf
	}
	if rskit > *candr {
		candi = &finiti
		candp = &finitp
		candr = &rskit
	}
	return *candi, *candp
}

// Score values per impact label
const (
	ImpactUnknownValue = 0.0
	ImpactLowValue     = 1.0
	ImpactMediumValue  = 2.0
	ImpactHighValue    = 3.0
	ImpactMaxValue     = 4.0
)

// Values for data classification
const (
	DataUnknownValue = 0.0
	DataPublicValue  = 1.0
	DataConfIntValue = 2.0
	DataConfResValue = 3.0
	DataConfSecValue = 4.0
)

type RRAAttribute struct {
	Attribute   string  `json:"attribute"`
	Impact      float64 `json:"impact"`
	Probability float64 `json:"probability"`
}

// Describes calculated risk for a service, based on an RRA and known
// data points
type Risk struct {
	RRA RRAService `json:"rra"` // The RRA we are describing

	// The attribute from the RRA we use as the basis for risk calculations
	// (business impact) for the service. For example, this could be "reputation",
	// "productivity", or "financial" depending on which attribute in the RRA
	// yields the highest defined risk.
	//
	// Previous versions of this would generate scenarios across all attributes
	// in the RRA. This behavior is not necessarily desirable as it can end up
	// devaluing high impact attributes when we consider the entire set combined.
	UsedRRAAttrib RRAAttribute

	Risk struct {
		WorstCase      float64 `json:"worst_case"`
		WorstCaseLabel string  `json:"worst_case_label"`
		Median         float64 `json:"median"`
		MedianLabel    string  `json:"median_label"`
		Average        float64 `json:"average"`
		AverageLabel   string  `json:"average_label"`
		DataClass      float64 `json:"data_classification"`
		Impact         float64 `json:"highest_business_impact"`
		ImpactLabel    string  `json:"highest_business_impact_label"`
	} `json:"risk"`

	Scenarios []RiskScenario `json:"scenarios"` // Risk scenarios
}

func (r *Risk) Validate() error {
	err := r.RRA.Validate()
	if err != nil {
		return err
	}
	return nil
}

// Stores information used to support probability for risk calculation; this
// generally would be created using control information and is combined with the
// RRA impact scores to produce estimated service risk
type RiskScenario struct {
	Name        string  `json:"name"` // Name describing the datapoint
	Probability float64 `json:"probability"`
	Impact      float64 `json:"impact"`
	Score       float64 `json:"score"`
	NoData      bool    `json:"nodata"`   // No data exists for proper calculation
	Coverage    string  `json:"coverage"` // Coverage (partial, complete, none, unknown)
}

// Validates a RiskScenario for consistency
func (r *RiskScenario) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("scenario must have a name")
	}
	if r.Coverage != "none" && r.Coverage != "partial" &&
		r.Coverage != "complete" && r.Coverage != "unknown" {
		return fmt.Errorf("scenario \"%v\" coverage invalid \"%v\"", r.Name, r.Coverage)
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
		// XXX Return low here if the value is set to unknown to handle older
		// format RRAs and still use the data in risk calculation; returning
		// valid data here is important for riskFindHighestImpact()
		return ImpactLowValue, nil
	}
	return 0, fmt.Errorf("invalid impact label %v", l)
}

// Convert an impact label into the numeric representation from 1 - 4 for
// that label
func DataValueFromLabel(l string) (float64, error) {
	switch l {
	case "confidential secret":
		return DataConfSecValue, nil
	case "confidential restricted":
		return DataConfResValue, nil
	case "confidential internal":
		return DataConfIntValue, nil
	case "public":
		return DataPublicValue, nil
	case "unknown":
		return DataUnknownValue, nil
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

// Given a risk score from 1 - 16, convert that sore into
// the string value that represents the risk
func NormalLabelFromValue(v float64) string {
	if v >= 13 {
		return "maximum"
	} else if v >= 9 {
		return "high"
	} else if v >= 5 {
		return "medium"
	}
	return "low"
}

// RawRRA defines a structure as we expect to see from a tool submitting
// an RRA to serviceapi (e.g., rra2json). The RRA document itself contains
// a large number of fields, but in this case we just reference the ones we
// need to exist and normalize for risk calculations.
type RawRRA struct {
	Details      RawRRADetails `json:"details"`
	LastModified time.Time     `json:"lastmodified"`
}

// XXX TEMP
type RRAService RRA

// Convert a RawRRA to an RRA
func (r *RawRRA) ToRRA() (ret RRA) {
	ret.Name = r.Details.Metadata.Service
	ret.DefData = r.Details.Data.Default
	ret.LastUpdated = r.LastModified

	ret.AvailRepImpact = r.Details.Risk.Availability.Reputation.Impact
	ret.AvailPrdImpact = r.Details.Risk.Availability.Productivity.Impact
	ret.AvailFinImpact = r.Details.Risk.Availability.Finances.Impact
	ret.IntegRepImpact = r.Details.Risk.Integrity.Reputation.Impact
	ret.IntegPrdImpact = r.Details.Risk.Integrity.Productivity.Impact
	ret.IntegFinImpact = r.Details.Risk.Integrity.Finances.Impact
	ret.ConfiRepImpact = r.Details.Risk.Confidentiality.Reputation.Impact
	ret.ConfiPrdImpact = r.Details.Risk.Confidentiality.Productivity.Impact
	ret.ConfiFinImpact = r.Details.Risk.Confidentiality.Finances.Impact

	ret.AvailRepProb = r.Details.Risk.Availability.Reputation.Probability
	ret.AvailPrdProb = r.Details.Risk.Availability.Productivity.Probability
	ret.AvailFinProb = r.Details.Risk.Availability.Finances.Probability
	ret.IntegRepProb = r.Details.Risk.Integrity.Reputation.Probability
	ret.IntegPrdProb = r.Details.Risk.Integrity.Productivity.Probability
	ret.IntegFinProb = r.Details.Risk.Integrity.Finances.Probability
	ret.ConfiRepProb = r.Details.Risk.Confidentiality.Reputation.Probability
	ret.ConfiPrdProb = r.Details.Risk.Confidentiality.Productivity.Probability
	ret.ConfiFinProb = r.Details.Risk.Confidentiality.Finances.Probability

	return
}

func (r *RawRRA) Validate() error {
	return r.Details.validate()
}

type RawRRADetails struct {
	Metadata RawRRAMetadata `json:"metadata"`
	Risk     RawRRARisk     `json:"risk"`
	Data     RawRRAData     `json:"data"`
}

func (r *RawRRADetails) validate() error {
	err := r.Metadata.validate()
	if err != nil {
		return err
	}
	err = r.Risk.validate(r.Metadata.Service)
	if err != nil {
		return err
	}
	err = r.Data.validate(r.Metadata.Service)
	if err != nil {
		return err
	}
	return nil
}

type RawRRAMetadata struct {
	Service string `json:"service"`
}

func (r *RawRRAMetadata) validate() error {
	if r.Service == "" {
		return fmt.Errorf("rra has no service name")
	}
	// Do some sanitization of the service name if neccessary
	r.Service = strings.Replace(r.Service, "\n", " ", -1)
	r.Service = strings.TrimSpace(r.Service)
	return nil
}

type RawRRAData struct {
	Default string `json:"default"`
}

func (r *RawRRAData) validate(s string) error {
	if r.Default == "" {
		return fmt.Errorf("rra has no default data classification")
	}
	// Sanitize the data classification
	// XXX This should likely be checked against a list of known valid
	// strings, and we just reject importing an RRA that has a data
	// classification value we don't know about.
	r.Default = strings.ToLower(r.Default)
	// Convert from some older classification values
	switch r.Default {
	case "internal":
		r.Default = "confidential internal"
	case "restricted":
		r.Default = "confidential restricted"
	case "secret":
		r.Default = "confidential secret"
	}
	return nil
}

type RawRRARisk struct {
	Confidentiality RawRRARiskAttr `json:"confidentiality"`
	Integrity       RawRRARiskAttr `json:"integrity"`
	Availability    RawRRARiskAttr `json:"availability"`
}

func (r *RawRRARisk) validate(s string) error {
	err := r.Confidentiality.validate(s)
	if err != nil {
		return err
	}
	err = r.Integrity.validate(s)
	if err != nil {
		return err
	}
	err = r.Availability.validate(s)
	if err != nil {
		return err
	}
	return nil
}

type RawRRARiskAttr struct {
	Reputation   RawRRAMeasure `json:"reputation"`
	Finances     RawRRAMeasure `json:"finances"`
	Productivity RawRRAMeasure `json:"productivity"`
}

func (r *RawRRARiskAttr) validate(s string) error {
	err := r.Reputation.validate(s)
	if err != nil {
		return err
	}
	err = r.Finances.validate(s)
	if err != nil {
		return err
	}
	err = r.Productivity.validate(s)
	if err != nil {
		return err
	}
	return nil
}

type RawRRAMeasure struct {
	Impact      string `json:"impact"`
	Probability string `json:"probability"`
}

func (r *RawRRAMeasure) validate(s string) (err error) {
	r.Impact, err = SanitizeImpactLabel(r.Impact)
	if err != nil {
		return err
	}
	// XXX If the probability value is unset, just default it to unknown
	// here and continue. We can proceed without this value, if we at least
	// have the impact. Without this though certain calculation datapoints
	// may not be possible.
	if r.Probability == "" {
		r.Probability = "unknown"
	}
	r.Probability, err = SanitizeImpactLabel(r.Probability)
	if err != nil {
		return err
	}
	return nil
}
