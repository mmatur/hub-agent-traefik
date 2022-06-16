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

package metrics

import (
	"context"
	"fmt"

	dto "github.com/prometheus/client_model/go"
	"github.com/traefik/hub-agent-traefik/pkg/traefik"
)

// Metric names.
const (
	MetricRequestDuration     = "request_duration"
	MetricRequests            = "requests"
	MetricRequestErrors       = "request_errors"
	MetricRequestClientErrors = "request_client_errors"
)

// Metric represents a metric object.
type Metric interface {
	EdgeIngressName() string
	IngressName() string
	ServiceName() string
}

// Counter represents a counter metric.
type Counter struct {
	Name        string
	EdgeIngress string
	Ingress     string
	Service     string
	Value       uint64
}

// CounterFromMetric returns a counter metric from a prometheus
// metric.
func CounterFromMetric(m *dto.Metric) uint64 {
	c := m.Counter
	if c == nil {
		return 0
	}

	return uint64(c.GetValue())
}

// EdgeIngressName returns the metric edge ingress name.
func (c Counter) EdgeIngressName() string {
	return c.EdgeIngress
}

// IngressName returns the metric ingress name.
func (c Counter) IngressName() string {
	return c.Ingress
}

// ServiceName returns the metric service name.
func (c Counter) ServiceName() string {
	return c.Service
}

// Histogram represents a histogram metric.
type Histogram struct {
	Name        string
	Relative    bool
	EdgeIngress string
	Ingress     string
	Service     string
	Sum         float64
	Count       uint64
}

// HistogramFromMetric returns a histogram metric from a prometheus
// metric.
func HistogramFromMetric(m *dto.Metric) *Histogram {
	hist := m.Histogram
	if hist == nil || hist.GetSampleCount() == 0 {
		return nil
	}

	return &Histogram{
		Sum:   hist.GetSampleSum(),
		Count: hist.GetSampleCount(),
	}
}

// EdgeIngressName returns the metric edge ingress name.
func (h Histogram) EdgeIngressName() string {
	return h.EdgeIngress
}

// IngressName returns the metric ingress name.
func (h Histogram) IngressName() string {
	return h.Ingress
}

// ServiceName returns the metric service name.
func (h Histogram) ServiceName() string {
	return h.Service
}

// Scraper scrapes metrics from Prometheus.
type Scraper struct {
	traefik       *traefik.Client
	traefikParser TraefikParser
}

// NewScraper returns a scraper instance with parser p.
func NewScraper(traefikClient *traefik.Client) *Scraper {
	return &Scraper{
		traefik:       traefikClient,
		traefikParser: NewTraefikParser(),
	}
}

// Scrape returns metrics scraped from all targets.
func (s *Scraper) Scrape(ctx context.Context) ([]Metric, error) {
	// This is a naive approach and should be dealt with
	// as an iterator later to control the amount of RAM
	// used while scraping many targets with many services.
	// e.g. 100 pods * 4000 services * 4 metrics = bad news bears (1.6 million)

	p := s.traefikParser
	var m []Metric

	raw, err := s.traefik.GetMetrics(ctx)
	if err != nil {
		return []Metric{}, fmt.Errorf("unable to get metrics from target: %w", err)
	}

	for _, v := range raw {
		m = append(m, p.Parse(v)...)
	}

	return m, nil
}
