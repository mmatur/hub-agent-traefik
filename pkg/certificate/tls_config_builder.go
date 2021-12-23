package certificate

import (
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
)

// TraefikManager allows pushing dynamic configurations to a TraefikManager instance.
type TraefikManager interface {
	SetTLSConfig(cfg *dynamic.TLSConfiguration)
}

// TLSConfigBuilder builds Traefik TLS configurations.
type TLSConfigBuilder struct {
	traefik TraefikManager
}

// NewTLSConfigBuilder returns a new TLSConfigBuilder.
func NewTLSConfigBuilder(traefik TraefikManager) *TLSConfigBuilder {
	return &TLSConfigBuilder{
		traefik: traefik,
	}
}

// UpdateConfig updates Traefik with a TLS configuration containing given certs.
func (m TLSConfigBuilder) UpdateConfig(certs []Certificate) error {
	certAndStores := make([]*tls.CertAndStores, 0, len(certs))
	for _, cert := range certs {
		certAndStores = append(certAndStores, &tls.CertAndStores{
			Certificate: tls.Certificate{
				CertFile: cert.Cert,
				KeyFile:  cert.Key,
			},
		})
	}

	m.traefik.SetTLSConfig(&dynamic.TLSConfiguration{Certificates: certAndStores})

	return nil
}
