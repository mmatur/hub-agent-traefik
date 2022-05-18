package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) (*Client, *http.ServeMux) {
	t.Helper()

	mux := http.NewServeMux()

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := NewClient(srv.URL, "token")
	require.NoError(t, err)
	c.httpClient = srv.Client()

	return c, mux
}

func TestClient_GetEdgeIngress(t *testing.T) {
	tests := []struct {
		desc              string
		wantEdgeIngresses []Ingress
		wantStatusCode    int
		wantError         require.ErrorAssertionFunc
	}{
		{
			desc: "get edge ingresses",
			wantEdgeIngresses: []Ingress{
				{
					WorkspaceID: "workspace-id",
					ClusterID:   "cluster-id",
					Namespace:   "namespace",
					Name:        "name",
					Domain:      "https://majestic-beaver-123.traefik-hub.io",
					Version:     "version",
					Service: Service{
						ID:   "service-id",
						Name: "service-name",
						IP:   "127.0.0.1",
						Port: 8080,
					},
					ACP: &ACPInfo{
						Name: "acp-name",
					},
					CreatedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond),
					UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
				},
			},
			wantStatusCode: http.StatusOK,
			wantError:      require.NoError,
		},
		{
			desc:           "internal server error",
			wantStatusCode: http.StatusInternalServerError,
			wantError: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorAs(t, err, &APIError{})
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			var callCount int

			c, mux := setup(t)

			mux.HandleFunc("/edge-ingresses", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodGet {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer token" {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				rw.WriteHeader(test.wantStatusCode)
				err := json.NewEncoder(rw).Encode(test.wantEdgeIngresses)
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
					return
				}
			})

			gotEdgeIngresses, err := c.GetEdgeIngresses(context.Background())
			test.wantError(t, err)

			require.Equal(t, 1, callCount)
			assert.Equal(t, test.wantEdgeIngresses, gotEdgeIngresses)
		})
	}
}

func TestClient_GetACPs(t *testing.T) {
	tests := []struct {
		desc           string
		wantACPs       []ACP
		wantStatusCode int
		wantError      require.ErrorAssertionFunc
	}{
		{
			desc: "get edge ingresses",
			wantACPs: []ACP{
				{
					ID:          "acp-id",
					WorkspaceID: "workspace-id",
					ClusterID:   "cluster-id",
					Version:     "version",
					Name:        "name",
					BasicAuth: &ACPBasicDigestAuthConfig{
						Users:                    []string{"toto"},
						Realm:                    "foo",
						StripAuthorizationHeader: false,
						ForwardUsernameHeader:    "Authorization",
					},
					CreatedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond),
					UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
				},
			},
			wantStatusCode: http.StatusOK,
			wantError:      require.NoError,
		},
		{
			desc:           "internal server error",
			wantStatusCode: http.StatusInternalServerError,
			wantError: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorAs(t, err, &APIError{})
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			var callCount int

			c, mux := setup(t)

			mux.HandleFunc("/acps", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodGet {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer token" {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				rw.WriteHeader(test.wantStatusCode)
				err := json.NewEncoder(rw).Encode(test.wantACPs)
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
					return
				}
			})

			gotACPs, err := c.GetACPs(context.Background())
			test.wantError(t, err)

			require.Equal(t, 1, callCount)
			assert.Equal(t, test.wantACPs, gotACPs)
		})
	}
}
