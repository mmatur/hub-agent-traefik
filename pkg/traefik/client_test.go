package traefik

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMTLS(t *testing.T) {
	caPath := "./fixtures/rootCA.pem"
	caPool, err := loadCA(caPath)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		b, err2 := json.Marshal(RunTimeRepresentation{})
		require.NoError(t, err2)
		_, err2 = rw.Write(b)
		require.NoError(t, err2)
	})

	serverCertificate, err := tls.LoadX509KeyPair(
		"./fixtures/proxy.traefik-client.pem",
		"./fixtures/proxy.traefik-client-key.pem")
	require.NoError(t, err)

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientCAs:    caPool,
		ServerName:   "proxy.traefik",
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	certPath := "./fixtures/agent.traefik-client.pem"
	keyPath := "./fixtures/agent.traefik-client-key.pem"
	client, err := NewClient(ts.URL, false, caPath, certPath, keyPath)
	require.NoError(t, err)

	dynamic, err := client.GetDynamic(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, dynamic)
}
