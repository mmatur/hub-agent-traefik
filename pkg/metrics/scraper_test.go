package metrics_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/hub-agent-traefik/pkg/metrics"
	"github.com/traefik/hub-agent-traefik/pkg/traefik"
)

func setupTraefikClient(t *testing.T) *traefik.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
			return
		}

		file, err := os.Open("testdata/traefik-metrics.txt")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.WriteHeader(http.StatusOK)
		_, _ = io.Copy(rw, file)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, err := traefik.NewClient(srv.URL, true, "", "", "")
	require.NoError(t, err)

	return client
}

func TestScraper_ScrapeTraefik(t *testing.T) {
	traefikClient := setupTraefikClient(t)
	s := metrics.NewScraper(traefikClient)

	got, err := s.Scrape(context.Background())
	require.NoError(t, err)

	// router
	assert.Contains(t, got, &metrics.Histogram{Name: metrics.MetricRequestDuration, Ingress: "myIngress-default-example-com", Sum: 0.0137623, Count: 1})
	assert.Contains(t, got, &metrics.Histogram{Name: metrics.MetricRequestDuration, Ingress: "default-myIngressRoute-6f97418635c7e18853da", Sum: 0.0216373, Count: 1})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Ingress: "myIngress-default-example-com", Value: 2})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequestClientErrors, Ingress: "myIngress-default-example-com", Value: 4})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequestErrors, Ingress: "myIngress-default-example-com", Value: 6})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, Ingress: "default-myIngressRoute-6f97418635c7e18853da", Value: 1})
	require.Len(t, got, 8)
}
