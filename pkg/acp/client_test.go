package acp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/neo-agent/pkg/acp/jwt"
)

func TestClient_GetACPs(t *testing.T) {
	resp := []acpResp{
		{
			Name: "jwt",
			Config: Config{
				JWT: &jwt.Config{
					SigningSecret: "secret",
				},
				Ingresses: []string{"ingress"},
			},
		},
	}

	want := map[string]Config{
		"jwt": {
			JWT: &jwt.Config{
				SigningSecret: "secret",
			},
			Ingresses: []string{"ingress"},
		},
	}

	var acpsCallCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpsCallCount++

		assert.Equal(t, "/acps", r.URL.Path)
		assert.Equal(t, "Bearer some_test_token", r.Header.Get("Authorization"))

		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(srv.URL, "some_test_token")
	require.NoError(t, err)

	got, err := client.GetACPs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, acpsCallCount)

	assert.Equal(t, want, got)
}
