package acp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPHandler_ServeHTTP(t *testing.T) {
	h := newHTTPHandler()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	h2 := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	h.Update(h2)

	resp, err = http.Get(server.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
