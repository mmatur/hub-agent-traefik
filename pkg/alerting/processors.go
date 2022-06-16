/*
Copyright (C) 2022 Traefik Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package alerting

import (
	"errors"
	"fmt"
	"time"

	"github.com/traefik/hub-agent-traefik/pkg/metrics"
)

// DataPointsFinder is capable of finding data points for given criteria.
type DataPointsFinder interface {
	FindByIngressAndService(table, ingress, service string, from, to time.Time) (metrics.DataPoints, error)
	FindByService(table, service string, from, to time.Time) metrics.DataPoints
	FindByEdgeIngress(table, edgeIngress string, from, to time.Time) metrics.DataPoints
	FindByIngress(table, ingress string, from, to time.Time) metrics.DataPoints
}

// ThresholdProcessor processes threshold rules.
type ThresholdProcessor struct {
	dataPoints DataPointsFinder

	nowFunc func() time.Time
}

// NewThresholdProcessor returns a threshold processor.
func NewThresholdProcessor(dataPoints DataPointsFinder) *ThresholdProcessor {
	return &ThresholdProcessor{
		dataPoints: dataPoints,
		nowFunc:    time.Now,
	}
}

// Process processes a threshold rule returning an alert or nil.
func (p *ThresholdProcessor) Process(rule *Rule) (*Alert, error) {
	table := rule.Threshold.Table()
	granularity := rule.Threshold.Granularity()

	// Compute the time range (inclusive) the alert wants to be triggered on. The granularity is subtracted to
	// avoid capturing the last data point which is not yet complete.
	to := p.nowFunc().UTC().Truncate(granularity).Add(-granularity)
	from := to.Add(-rule.Threshold.TimeRange)

	var dataPoints metrics.DataPoints

	switch {
	case rule.Ingress != "" && rule.Service != "":
		var err error

		dataPoints, err = p.dataPoints.FindByIngressAndService(table, rule.Ingress, rule.Service, from, to)
		if err != nil {
			return nil, err
		}
	case rule.Service != "":
		dataPoints = p.dataPoints.FindByService(table, rule.Service, from, to)
	case rule.EdgeIngress != "":
		dataPoints = p.dataPoints.FindByEdgeIngress(table, rule.Ingress, from, to)
	case rule.Ingress != "":
		dataPoints = p.dataPoints.FindByIngress(table, rule.Ingress, from, to)
	default:
		return nil, errors.New("invalid rule")
	}

	var points []Point
	for _, datapoint := range dataPoints {
		value, err := getValue(rule.Threshold.Metric, datapoint)
		if err != nil {
			return nil, err
		}

		points = append(points, Point{
			Timestamp: datapoint.Timestamp,
			Value:     value,
		})
	}

	// Check if an alert has to be raised.
	count := p.countOccurrences(rule, points)
	if count < rule.Threshold.Occurrence {
		return nil, nil
	}

	return &Alert{
		RuleID:    rule.ID,
		Ingress:   rule.Ingress,
		Service:   rule.Service,
		Points:    points,
		Threshold: rule.Threshold,
	}, nil
}

func (p *ThresholdProcessor) countOccurrences(rule *Rule, pnts []Point) int {
	var count int
	for _, pnt := range pnts {
		if rule.Threshold.Condition.Above && pnt.Value > rule.Threshold.Condition.Value {
			count++
		} else if !rule.Threshold.Condition.Above && pnt.Value < rule.Threshold.Condition.Value {
			count++
		}
	}

	return count
}

func getValue(metric string, pnt metrics.DataPoint) (float64, error) {
	switch metric {
	case "requestsPerSecond":
		return pnt.ReqPerS, nil
	case "requestErrorsPerSecond":
		return pnt.RequestErrPerS, nil
	case "requestClientErrorsPerSecond":
		return pnt.RequestClientErrPerS, nil
	case "averageResponseTime":
		return pnt.AvgResponseTime, nil
	default:
		return 0, fmt.Errorf("invalid metric type: %s", metric)
	}
}
