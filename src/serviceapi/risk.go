// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"github.com/montanaflynn/stats"
	slib "servicelib"
)

// Calculate a risk scenario, uses compliance data as probability metric
func riskComplianceScenario(op opContext, rs *slib.RRAServiceRisk,
	src slib.RRAAttribute, desc string) error {
	// Calculate our step value based on the number of compliance checks
	// that have been executed for supporting hosts
	//
	// XXX We should filter compliance checks here that do not make sense
	// for a the service (e.g., filter out MAXIMUM related checks for low
	// requirement services, but this information isn't really captured
	// anywhere right now
	totalcnt := 0
	coverage := "complete"
	for _, x := range rs.RRA.SupportGrps {
		for _, y := range x.Host {
			var inc int
			inc += y.CompStatus.HighFail
			inc += y.CompStatus.HighPass
			inc += y.CompStatus.MediumFail
			inc += y.CompStatus.MediumPass
			inc += y.CompStatus.LowFail
			inc += y.CompStatus.LowPass
			totalcnt += inc

			// See if a host reported nothing, if so downgrade the
			// coverage
			if inc == 0 {
				coverage = "partial"
			}
		}
	}
	// If totalcnt is zero, we didn't have any data points.
	if totalcnt == 0 {
		ndp := slib.RiskScenario{
			Name:     "Compliance scenario for " + desc,
			NoData:   true,
			Coverage: "none",
		}
		rs.Scenarios = append(rs.Scenarios, ndp)
		return nil
	}
	stepv := 3.0 / float64(totalcnt)
	scr := 1.0
	for _, x := range rs.RRA.SupportGrps {
		for _, y := range x.Host {
			scr += stepv * float64(y.CompStatus.HighFail)
			scr += stepv * float64(y.CompStatus.MediumFail)
			scr += stepv * float64(y.CompStatus.LowFail)
		}
	}

	newscen := slib.RiskScenario{
		Name:        "Compliance scenario for " + desc,
		Impact:      src.Impact,
		Probability: scr,
		Score:       src.Impact * scr,
		Coverage:    coverage,
		NoData:      false,
	}
	err := newscen.Validate()
	if err != nil {
		return err
	}
	rs.Scenarios = append(rs.Scenarios, newscen)

	return nil
}

func riskVulnerabilityScenario(op opContext, rs *slib.RRAServiceRisk,
	src slib.RRAAttribute, desc string) error {
	// The score here will range from 1 to 4, and will be set to the
	// score associated with the highest vulnerability impact value
	// identified on the hosts in scope. For example, a single maximum
	// impact vulnerability will result in a probability score of 4.0.
	//
	// This could probably be changed to be a little more lenient.
	highest := 1.0
	for _, x := range rs.RRA.SupportGrps {
		for _, y := range x.Host {
			// If we have already seen a max impact issue, just break
			if highest == 4.0 {
				break
			}
			if y.VulnStatus.Medium > 0 && highest < 2.0 {
				highest = 2.0
			}
			if y.VulnStatus.High > 0 && highest < 3.0 {
				highest = 3.0
			}
			if y.VulnStatus.Maximum > 0 && highest < 4.0 {
				highest = 4.0
			}
		}
	}
	// Set coverage to unknown as currently it is not possible to tell
	// if all hosts are being assessed; we can't go by there being no
	// known issues on the asset.
	newscen := slib.RiskScenario{
		Name:        "Vulnerability scenario for " + desc,
		Impact:      src.Impact,
		Probability: highest,
		Score:       highest * src.Impact,
		Coverage:    "unknown",
	}
	err := newscen.Validate()
	if err != nil {
		return err
	}
	rs.Scenarios = append(rs.Scenarios, newscen)

	return nil
}

// Calculate a risk scenario, uses information from the RRA
func riskRRAScenario(op opContext, rs *slib.RRAServiceRisk, src slib.RRAAttribute, desc string) error {
	newscen := slib.RiskScenario{
		Name:     "RRA derived risk for " + desc,
		Coverage: "none",
		NoData:   true,
	}
	if src.Impact != 0 && src.Probability != 0 {
		newscen.Probability = src.Probability
		newscen.Impact = src.Impact
		newscen.Score = src.Impact * src.Probability
		newscen.Coverage = "complete"
		newscen.NoData = false
	}
	err := newscen.Validate()
	if err != nil {
		return err
	}
	rs.Scenarios = append(rs.Scenarios, newscen)
	return nil
}

// Finalize calculation of the risk using available datapoints
func riskFinalize(op opContext, rs *slib.RRAServiceRisk) error {
	var (
		rvals []float64
		err   error
	)
	for _, x := range rs.Scenarios {
		// If the scenario had no data, don't include it in the
		// final scoring
		if x.NoData {
			continue
		}
		rvals = append(rvals, x.Score)
	}
	rs.Risk.Median, err = stats.Median(rvals)
	if err != nil {
		return err
	}
	rs.Risk.MedianLabel = slib.NormalLabelFromValue(rs.Risk.Median)
	rs.Risk.Average, err = stats.Mean(rvals)
	if err != nil {
		return err
	}
	rs.Risk.AverageLabel = slib.NormalLabelFromValue(rs.Risk.Average)
	rs.Risk.WorstCase, err = stats.Max(rvals)
	if err != nil {
		return err
	}
	rs.Risk.WorstCaseLabel = slib.NormalLabelFromValue(rs.Risk.WorstCase)
	return nil
}

// Determine which attributes (e.g., conf, integ, avail) from the RRA
// we want to use was impact inputs for the risk scenarios.
func riskFindHighestImpact(rs *slib.RRAServiceRisk) error {
	rs.UsedRRAAttrib.Reputation.Impact,
		rs.UsedRRAAttrib.Reputation.Probability = rs.RRA.HighestRiskReputation()
	rs.UsedRRAAttrib.Productivity.Impact,
		rs.UsedRRAAttrib.Productivity.Probability = rs.RRA.HighestRiskProductivity()
	rs.UsedRRAAttrib.Financial.Impact,
		rs.UsedRRAAttrib.Financial.Probability = rs.RRA.HighestRiskFinancial()
	return nil
}

// Risk calculation entry function, evaluates RRA in rs using any known
// datapoints we have information for
func riskCalculation(op opContext, rs *slib.RRAServiceRisk) error {
	// Determine our highest impact value
	err := riskFindHighestImpact(rs)
	if err != nil {
		return err
	}
	err = riskRRAScenario(op, rs, rs.UsedRRAAttrib.Reputation, "reputation")
	if err != nil {
		return err
	}
	err = riskRRAScenario(op, rs, rs.UsedRRAAttrib.Productivity, "productivity")
	if err != nil {
		return err
	}
	err = riskRRAScenario(op, rs, rs.UsedRRAAttrib.Financial, "financial")
	if err != nil {
		return err
	}
	err = riskComplianceScenario(op, rs, rs.UsedRRAAttrib.Reputation, "reputation")
	if err != nil {
		return err
	}
	err = riskComplianceScenario(op, rs, rs.UsedRRAAttrib.Productivity, "productivity")
	if err != nil {
		return err
	}
	err = riskComplianceScenario(op, rs, rs.UsedRRAAttrib.Financial, "financial")
	if err != nil {
		return err
	}
	err = riskVulnerabilityScenario(op, rs, rs.UsedRRAAttrib.Reputation, "reputation")
	if err != nil {
		return err
	}
	err = riskVulnerabilityScenario(op, rs, rs.UsedRRAAttrib.Productivity, "productivity")
	if err != nil {
		return err
	}
	err = riskVulnerabilityScenario(op, rs, rs.UsedRRAAttrib.Financial, "financial")
	if err != nil {
		return err
	}
	err = riskFinalize(op, rs)
	if err != nil {
		return err
	}
	return nil
}
