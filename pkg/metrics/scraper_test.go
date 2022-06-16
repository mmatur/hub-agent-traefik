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
	assert.Contains(t, got, &metrics.Histogram{Name: metrics.MetricRequestDuration, EdgeIngress: "myIngress-default-example-com", Sum: 0.0137623, Count: 1})
	assert.Contains(t, got, &metrics.Histogram{Name: metrics.MetricRequestDuration, EdgeIngress: "default-myIngressRoute-6f97418635c7e18853da", Sum: 0.0216373, Count: 1})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, EdgeIngress: "myIngress-default-example-com", Value: 2})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequestClientErrors, EdgeIngress: "myIngress-default-example-com", Value: 4})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequestErrors, EdgeIngress: "myIngress-default-example-com", Value: 6})
	assert.Contains(t, got, &metrics.Counter{Name: metrics.MetricRequests, EdgeIngress: "default-myIngressRoute-6f97418635c7e18853da", Value: 1})
	require.Len(t, got, 8)
}
