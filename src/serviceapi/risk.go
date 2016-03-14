// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	slib "servicelib"
)

// Calculate a compliance related datapoint for the RRA. This function
// requires system group metadata be introduced into the RRA, which will
// contain compliance statistics for relevant hosts.
func riskComplianceDatapoint(op opContext, rs *slib.RRAServiceRisk) error {
	// Just use a default cap value of 1 here (uncapped)
	var dpCap = 1.0

	// Calculate our step value based on the number of compliance checks
	// that have been executed for supporting hosts
	//
	// XXX We should filter compliance checks here that do not make sense
	// for a the service (e.g., filter out MAXIMUM related checks for low
	// requirement services
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
		ndp := slib.RiskDatapoint{
			Name:     "Compliance checks",
			Weight:   2.0,
			Cap:      dpCap,
			NoData:   true,
			Coverage: "none",
		}
		rs.Datapoints = append(rs.Datapoints, ndp)
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

	ndp := slib.RiskDatapoint{
		Name:     "Compliance checks",
		Weight:   2.0,
		Score:    scr,
		Cap:      dpCap,
		Coverage: coverage,
	}
	err := ndp.Validate()
	if err != nil {
		return err
	}
	rs.Datapoints = append(rs.Datapoints, ndp)

	return nil
}

func riskVulnerabilityDatapoint(op opContext, rs *slib.RRAServiceRisk) error {
	// Just use a default cap value of 1 here (uncapped)
	var dpCap = 1.0

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
	coverage := "complete"
	ndp := slib.RiskDatapoint{
		Name:     "Vulnerability checks",
		Weight:   2.0,
		Score:    highest,
		Cap:      dpCap,
		Coverage: coverage,
	}
	err := ndp.Validate()
	if err != nil {
		return err
	}
	rs.Datapoints = append(rs.Datapoints, ndp)

	return nil
}

// Calculate a risk datapoint using the RRA highest impact and associated
// probability score
func riskRRADatapoint(op opContext, rs *slib.RRAServiceRisk) error {
	var (
		dpCap = 1.0
		err   error
	)

	ndp := slib.RiskDatapoint{
		Name:   "RRA derived probability",
		Weight: 1.0,
		Cap:    dpCap,
	}

	// If the probability is unknown, we can't create this datapoint
	if rs.HighestImpactProb == "unknown" {
		ndp.NoData = true
		ndp.Coverage = "none"
		rs.Datapoints = append(rs.Datapoints, ndp)
		return nil
	}

	ndp.Coverage = "complete"
	ndp.Score, err = slib.ImpactValueFromLabel(rs.HighestImpactProb)
	if err != nil {
		return err
	}
	rs.Datapoints = append(rs.Datapoints, ndp)

	return nil
}

// Finalize calculation of the risk using available datapoints
func riskFinalize(op opContext, rs *slib.RRAServiceRisk) error {
	var sval float64
	// Calculate our final risk score
	founddata := false
	for _, x := range rs.Datapoints {
		if x.NoData {
			continue
		}
		founddata = true
		sval += x.Cap * (x.Score * x.Weight)
	}
	if !founddata {
		// We had no valid data to support any calculation
		rs.WorstCase = 0
		rs.NormalRisk = 0
		rs.NormalLabel = slib.NormalLabelFromValue(rs.NormalRisk)
		return nil
	}
	tval, err := slib.ImpactValueFromLabel(rs.HighestImpact)
	if err != nil {
		return err
	}
	rs.RiskScore = tval * sval
	// Calculate what the highest possible risk score for the service is,
	// based on the data we have
	sval = 0
	for _, x := range rs.Datapoints {
		if x.NoData {
			continue
		}
		sval += x.Cap * (4 * x.Weight)
	}
	rs.WorstCase = tval * sval
	// Calculate the normalized value
	rs.NormalRisk = (rs.RiskScore * 100) / rs.WorstCase
	rs.NormalLabel = slib.NormalLabelFromValue(rs.NormalRisk)
	return nil
}

// Determine that highest known impact value from the RRA, which we will use
// as the impact input value in risk calculations
func riskFindHighestImpact(rs *slib.RRAServiceRisk) error {
	var (
		tv         float64
		err        error
		labelValue = 1.0
		probLabel  = "unknown"
	)
	f := func(x float64, y float64, prob string) (float64, string) {
		if y > x {
			return y, prob
		}
		return x, probLabel
	}
	tv, err = slib.ImpactValueFromLabel(rs.RRA.AvailRepImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.AvailRepProb)
	tv, err = slib.ImpactValueFromLabel(rs.RRA.AvailPrdImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.AvailPrdProb)
	tv, err = slib.ImpactValueFromLabel(rs.RRA.AvailFinImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.AvailFinProb)
	tv, err = slib.ImpactValueFromLabel(rs.RRA.IntegRepImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.IntegRepProb)
	tv, err = slib.ImpactValueFromLabel(rs.RRA.IntegPrdImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.IntegPrdProb)
	tv, err = slib.ImpactValueFromLabel(rs.RRA.IntegFinImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.IntegFinProb)
	tv, err = slib.ImpactValueFromLabel(rs.RRA.ConfiRepImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.ConfiRepProb)
	tv, err = slib.ImpactValueFromLabel(rs.RRA.ConfiPrdImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.ConfiPrdProb)
	tv, err = slib.ImpactValueFromLabel(rs.RRA.ConfiFinImpact)
	if err != nil {
		return err
	}
	labelValue, probLabel = f(labelValue, tv, rs.RRA.ConfiFinProb)
	rs.HighestImpact, err = slib.ImpactLabelFromValue(labelValue)
	if err != nil {
		return err
	}
	rs.HighestImpactProb = probLabel
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
	err = riskRRADatapoint(op, rs)
	if err != nil {
		return err
	}
	err = riskComplianceDatapoint(op, rs)
	if err != nil {
		return err
	}
	err = riskVulnerabilityDatapoint(op, rs)
	if err != nil {
		return err
	}
	err = riskFinalize(op, rs)
	if err != nil {
		return err
	}
	return nil
}
