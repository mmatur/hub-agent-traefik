package metrics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/hub-agent-traefik/pkg/metrics"
)

func TestScraper_ScrapeTraefik(t *testing.T) {
	srvURL := startServer(t, "testdata/traefik-metrics.txt")

	s := metrics.NewScraper(http.DefaultClient)

	got, err := s.Scrape(context.Background(), srvURL)
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

func startServer(t *testing.T, file string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Clean(file))
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}
