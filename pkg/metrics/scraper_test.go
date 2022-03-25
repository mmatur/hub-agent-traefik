package metrics_test

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/hub-agent-traefik/pkg/metrics"
)

type traefikScraperMock struct{}

func (s *traefikScraperMock) GetMetrics(_ context.Context) ([]*dto.MetricFamily, error) {
	file, err := os.Open("testdata/traefik-metrics.txt")
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	textParser := expfmt.TextParser{}

	metricFamilies, err := textParser.TextToMetricFamilies(bufio.NewReader(file))
	if err != nil {
		return nil, fmt.Errorf("text to metrics families: %w", err)
	}

	var m []*dto.MetricFamily
	for _, mf := range metricFamilies {
		m = append(m, mf)
	}

	return m, nil
}

func TestScraper_ScrapeTraefik(t *testing.T) {
	s := metrics.NewScraper(&traefikScraperMock{})

	got, err := s.Scrape(context.Background())
	require.NoError(t, err)

	// service
	assert.Contains(t, got, &metrics.Histogram{Name: metrics.MetricRequestDuration, Service: "default-whoami-80@docker", Sum: 0.021072671000000005, Count: 12})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Service: "default-whoami-sdfsdfsdsd@docker", Value: 12})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Service: "default-whoami-80@docker", Value: 14})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequestClientErrors, Service: "default-whoami-80@docker", Value: 14})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Service: "default-whoami2-80@docker", Value: 16})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequestErrors, Service: "default-whoami2-80@docker", Value: 16})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Service: "default-whoami3-80@docker", Value: 15})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequestErrors, Service: "default-whoami3-80@docker", Value: 15})

	// router
	assert.Contains(t, got, &metrics.Histogram{Name: metrics.MetricRequestDuration, Ingress: "myIngress-default-example-com@docker", Sum: 0.0137623, Count: 1})
	assert.Contains(t, got, &metrics.Histogram{Name: metrics.MetricRequestDuration, Ingress: "default-myIngressRoute-6f97418635c7e18853da@docker", Sum: 0.0216373, Count: 1})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Ingress: "myIngress-default-example-com@docker", Value: 2})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Ingress: "default-myIngressRoute-6f97418635c7e18853da@docker", Value: 1})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Service: "default-myIngressRoute-6f97418635c7e18853da@docker", Value: 17})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequestErrors, Service: "default-myIngressRoute-6f97418635c7e18853da@docker", Value: 17})

	require.Len(t, got, 14)
}
