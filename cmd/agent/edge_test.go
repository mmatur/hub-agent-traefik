package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/traefik/hub-agent-traefik/pkg/certificate"
	"github.com/traefik/hub-agent-traefik/pkg/edge"
	"github.com/traefik/hub-agent-traefik/pkg/topology"
	"github.com/traefik/hub-agent-traefik/pkg/traefik"
)

type providerMock struct{}

func (m providerMock) Watch(ctx context.Context, clusterID string, fn func(map[string]*topology.Service)) error {
	return nil
}

func (m providerMock) GetIP(ctx context.Context, containerName, network string) (string, error) {
	return "127.0.0.1", nil
}

func TestEdgeUpdater_Update(t *testing.T) {
	certClient := setupCertClient(t)
	traefikClient := setupTraefikClient(t)

	ingresses := []edge.Ingress{
		{
			WorkspaceID: "workspace-id",
			ClusterID:   "cluster-id",
			Namespace:   "namespace",
			Name:        "name",
			Domain:      "https://majestic-beaver-123.traefik-hub.io",
			Version:     "version",
			Service: edge.Service{
				ID:      "service-id",
				Name:    "service-name",
				Network: "foo_network",
				Port:    8080,
			},
			ACP: &edge.ACPInfo{
				Name: "acp-name",
			},
			CreatedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond),
			UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
		},
	}

	acps := []edge.ACP{
		{
			ID:          "acp-id",
			WorkspaceID: "workspace-id",
			ClusterID:   "cluster-id",
			Version:     "version",
			Name:        "name",
			BasicAuth: &edge.ACPBasicDigestAuthConfig{
				Users:                    []string{"toto"},
				Realm:                    "foo",
				StripAuthorizationHeader: false,
				ForwardUsernameHeader:    "Authorization",
			},
			CreatedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond),
			UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
		},
	}

	edgeUpdater := NewEdgeUpdater(certClient, traefikClient, providerMock{}, "127.0.0.1", 2)
	err := edgeUpdater.Update(context.Background(), ingresses, acps)
	require.NoError(t, err)
}

func setupTraefikClient(t *testing.T) *traefik.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/config", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
			return
		}

		rw.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, err := traefik.NewClient(srv.URL, true, "", "", "")
	require.NoError(t, err)

	return client
}

func setupCertClient(t *testing.T) *certificate.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/wildcard-certificate", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
			return
		}

		file, err := os.Open("fixtures/cert.json")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.WriteHeader(http.StatusOK)
		_, _ = io.Copy(rw, file)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, err := certificate.NewClient(srv.URL, "token")
	require.NoError(t, err)

	return client
}
