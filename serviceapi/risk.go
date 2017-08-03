// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lib/pq"
	"github.com/montanaflynn/stats"
	slib "github.com/mozilla/service-map/servicelib"
	"time"
)

// riskRRAScenario calculates a risk scenario for a given RRA using the probability
// associated with the impact score we decided to use based on riskFindHighestImpact. For
// example, if a reputation based attribute was selected, we will also use the probability
// that was associated with that attribute.
func riskRRAScenario(op opContext, rs *slib.Risk, src slib.RRAAttribute) error {
	newscen := slib.RiskScenario{
		Name: "RRA derived risk for " + src.Attribute,
	}
	if src.Impact != 0 && src.Probability != 0 {
		// Cap the maximum probability we will use on the RRA at 2.0 (MEDIUM).
		// Some older RRAs (and some new ones) don't have correct probability
		// values set; once these are revisted we might be able to remove the
		// cap but for now set it to 2.
		if src.Probability > 2 {
			newscen.Probability = 2
		} else {
			newscen.Probability = src.Probability
		}
		newscen.Impact = src.Impact
		newscen.Score = newscen.Impact * newscen.Probability
	}
	err := newscen.Validate()
	if err != nil {
		return err
	}
	rs.Scenarios = append(rs.Scenarios, newscen)
	return nil
}

// riskIndicatorScenarios creates a risk scenario for each distinct event_source for the
// assets which are part of the service
func riskIndicatorScenarios(op opContext, rs *slib.Risk, src slib.RRAAttribute) error {
	var err error
	// First build a map, where the key is a distinct event source name from an indicator
	// and the value is the highest likelihood reported for that event source for all assets
	// which are part of the service.
	scenmap := make(map[string]float64)
	for _, g := range rs.RRA.Groups {
		for _, a := range g.Assets {
			for _, i := range a.Indicators {
				if v, ok := scenmap[i.EventSource]; ok {
					tv, err := slib.ImpactValueFromLabel(i.Likelihood)
					if err != nil {
						return err
					}
					if tv > v {
						scenmap[i.EventSource] = tv
					}
				} else {
					scenmap[i.EventSource], err = slib.ImpactValueFromLabel(i.Likelihood)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	// Next, we generate a scenario for each element in the map
	for k, v := range scenmap {
		newscen := slib.RiskScenario{
			Name: k + " derived risk for " + src.Attribute,
		}
		newscen.Probability = v
		newscen.Impact = src.Impact
		newscen.Score = newscen.Impact * newscen.Probability
		err := newscen.Validate()
		if err != nil {
			return err
		}
		rs.Scenarios = append(rs.Scenarios, newscen)
	}
	return nil
}

// riskFinalize takes into account all scenarios present in rs and calculates a final
// risk score for the RRA
func riskFinalize(op opContext, rs *slib.Risk) error {
	var (
		rvals []float64
		err   error
	)

	for _, x := range rs.Scenarios {
		rvals = append(rvals, x.Score)
	}

	// Note the highest business impact value that was determined from
	// the RRA. This can be used as an indication of the business impact
	// for the service.
	rs.Risk.Impact = rs.UsedRRAAttrib.Impact
	rs.Risk.ImpactLabel, err = slib.ImpactLabelFromValue(rs.Risk.Impact)
	if err != nil {
		return err
	}

	if len(rvals) == 0 {
		// This can occur if we have no metric data, including no valid
		// information in the RRA
		logf("error in risk calculation: %q has no valid scenarios", rs.RRA.Name)
		rs.Risk.Median = 0.0
		rs.Risk.Average = 0.0
		rs.Risk.WorstCase = 0.0
		rs.Risk.MedianLabel = "unknown"
		rs.Risk.AverageLabel = "unknown"
		rs.Risk.WorstCaseLabel = "unknown"
		rs.Risk.DataClass, err = slib.DataValueFromLabel(rs.RRA.DefData)
		return nil
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

	rs.Risk.DataClass, err = slib.DataValueFromLabel(rs.RRA.DefData)
	if err != nil {
		return err
	}
	return nil
}

// riskFindHighestImpact examines the RRA within rs, and determines which attribute
// (e.g., reputation, finances, productivity) has the highest impact score. This is
// the impact score that we will use for risk calculations.
func riskFindHighestImpact(rs *slib.Risk) error {
	var (
		repimp, repprob   float64
		prodimp, prodprob float64
		finimp, finprob   float64
		userisk           float64
		selectattr        string
	)
	repimp, repprob = rs.RRA.HighestRiskReputation()
	prodimp, prodprob = rs.RRA.HighestRiskProductivity()
	finimp, finprob = rs.RRA.HighestRiskFinancial()

	riskrep := repimp * repprob
	riskprod := prodimp * prodprob
	riskfin := finimp * finprob

	if riskrep > userisk {
		userisk = riskrep
		selectattr = "reputation"
	}
	if riskprod > userisk {
		userisk = riskprod
		selectattr = "productivity"
	}
	if riskfin > userisk {
		userisk = riskfin
		selectattr = "financial"
	}

	rs.UsedRRAAttrib.Attribute = selectattr
	switch selectattr {
	case "reputation":
		rs.UsedRRAAttrib.Impact = repimp
		rs.UsedRRAAttrib.Probability = repprob
	case "productivity":
		rs.UsedRRAAttrib.Impact = prodimp
		rs.UsedRRAAttrib.Probability = prodprob
	case "financial":
		rs.UsedRRAAttrib.Impact = finimp
		rs.UsedRRAAttrib.Probability = finprob
	default:
		return fmt.Errorf("riskFindHighestImpact found no valid attributes")
	}

	return nil
}

// riskCalculation evaluates and finalizes the risk for the RRA in rs, existing
// indicators are taken into account and rs is populated with the risk score.
func riskCalculation(op opContext, rs *slib.Risk) error {
	// Determine our highest impact value
	err := riskFindHighestImpact(rs)
	if err != nil {
		return err
	}
	err = riskRRAScenario(op, rs, rs.UsedRRAAttrib)
	if err != nil {
		return err
	}
	err = riskIndicatorScenarios(op, rs, rs.UsedRRAAttrib)
	if err != nil {
		return err
	}
	err = riskFinalize(op, rs)
	if err != nil {
		return err
	}
	return nil
}

// Given an RRA ID, return Risk representing calculated risk
// at the current time
func riskForRRA(op opContext, useCache bool, rraid int) (ret slib.Risk, err error) {
	// If the cache is desired, see if we have an entry in the cache for this RRA
	// and how old it is. If it is less than 4 hours old just return this.
	if useCache {
		var (
			ts  time.Time
			buf []byte
		)
		err = op.QueryRow(`SELECT timestamp, risk FROM risk WHERE
			rraid = $1 ORDER BY timestamp DESC LIMIT 1`, rraid).Scan(&ts, &buf)
		if err != nil && err != sql.ErrNoRows {
			return ret, err
		}
		// If no error was returned we got a valid hit from the cache, otherwise
		// no rows and proceed with calculation
		if err == nil {
			cutoff := time.Now().UTC().Add(-1 * (time.Minute * 60 * 4))
			if ts.After(cutoff) {
				logf("returning cached risk data for rra %v", rraid)
				err = json.Unmarshal(buf, &ret)
				if err != nil {
					return ret, err
				}
				err = ret.Validate()
				if err != nil {
					return ret, err
				}
				return ret, nil
			}
		}
	}

	r, err := getRRA(op, rraid)
	if err != nil {
		return ret, err
	}

	ret.RRA = r
	err = riskCalculation(op, &ret)
	if err != nil {
		return ret, err
	}
	err = ret.Validate()
	if err != nil {
		return ret, err
	}
	return ret, nil
}

// Cache entry point, called from risk cache routine to store risk document
// for a service at current point in time
func cacheRisk(op opContext, rraid int) error {
	logf("cacherisk: processing rraid %v", rraid)
	rs, err := riskForRRA(op, false, rraid)
	if err != nil {
		return err
	}
	buf, err := json.Marshal(&rs)
	if err != nil {
		return err
	}
	// Store the generated risk document in the risks table
	_, err = op.Exec(`INSERT INTO risk
		(rraid, timestamp, risk)
		VALUES
		($1, now(), $2)`, rraid, buf)
	if err != nil {
		return err
	}
	return nil
}

func riskCacheGetRRAs(op opContext) error {
	rows, err := op.Query(`SELECT rra.rraid, MAX(risk.timestamp)
		FROM rra LEFT OUTER JOIN risk ON rra.rraid = risk.rraid
		GROUP BY rra.rraid`)
	if err != nil {
		return err
	}
	dur, err := time.ParseDuration(cfg.General.RiskCacheEvery)
	if err != nil {
		return err
	}
	cutoff := time.Now().UTC().Add(-1 * dur)
	for rows.Next() {
		var (
			rraid int
			ts    pq.NullTime
		)
		err = rows.Scan(&rraid, &ts)
		if err != nil {
			rows.Close()
			return err
		}
		if ts.Valid {
			if ts.Time.After(cutoff) {
				continue
			}
		}
		err = cacheRisk(op, rraid)
		if err != nil {
			rows.Close()
			return err
		}
	}
	err = rows.Err()
	if err != nil {
		return err
	}
	return nil
}

func riskCache() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in risk cache routine: %v", e)
		}
	}()
	op := opContext{}
	op.newContext(dbconn, false, "riskcache")

	err := riskCacheGetRRAs(op)
	if err != nil {
		panic(err)
	}
}
