package basicauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/hub-agent-traefik/pkg/edge"
)

func TestBasicAuth_fail(t *testing.T) {
	cfg := &edge.ACPBasicDigestAuthConfig{
		Users: []string{"test"},
	}
	_, err := NewHandler(cfg, "authName")
	require.Error(t, err)

	cfg = &edge.ACPBasicDigestAuthConfig{
		Users: []string{"test:test"},
	}
	handler, err := NewHandler(cfg, "acp@my-ns")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.SetBasicAuth("test", "test")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestBasicAuth_userHeader(t *testing.T) {
	cfg := &edge.ACPBasicDigestAuthConfig{
		Users:                 []string{"test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/"},
		ForwardUsernameHeader: "User",
	}
	handler, err := NewHandler(cfg, "acp@my-ns")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.SetBasicAuth("test", "test")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test", rec.Header().Get("User"))
}
