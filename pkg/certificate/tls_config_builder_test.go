package certificate

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
	"github.com/traefik/genconf/dynamic/types"
)

type traefikManagerMock struct {
	setTLSConfig func(cfg *dynamic.TLSConfiguration)
}

func (m traefikManagerMock) SetTLSConfig(cfg *dynamic.TLSConfiguration) {
	m.setTLSConfig(cfg)
}

// CertClient allows managing certificates from the platform.
type CertClientMock struct {
	obtain func(domains []string) (Certificate, error)
}

func (c CertClientMock) Obtain(domains []string) (Certificate, error) {
	return c.obtain(domains)
}

func TestTLSConfigBuilder_ObtainCertificates_NoUpdateNeeded(t *testing.T) {
	tests := []struct {
		desc           string
		cfg            *dynamic.Configuration
		expectedTLSCfg *dynamic.TLSConfiguration
	}{
		{
			desc: "without tls conf",
			cfg: &dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo",
							Rule:        "Host(`foo`)",
						},
					},
				},
			},
			expectedTLSCfg: &dynamic.TLSConfiguration{},
		},
		{
			desc: "with empty tls conf",
			cfg: &dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo",
							Rule:        "Host(`foo`)",
							TLS:         &dynamic.RouterTLSConfig{},
						},
					},
				},
			},
			expectedTLSCfg: &dynamic.TLSConfiguration{},
		},
		{
			desc: "with unssuported tls certresolver",
			cfg: &dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo",
							Rule:        "Host(`foo`)",
							TLS: &dynamic.RouterTLSConfig{
								CertResolver: "acme",
								Domains: []types.Domain{
									{
										Main: "foo",
										SANs: []string{"foo"},
									},
								},
							},
						},
					},
				},
			},
			expectedTLSCfg: &dynamic.TLSConfiguration{},
		},
		{
			desc: "neither with domains nor with Host rule",
			cfg: &dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{
					Routers: map[string]*dynamic.Router{
						"foo": {
							EntryPoints: []string{"web"},
							Service:     "foo",
							Rule:        "PathPrefix(`/foo`)",
							TLS: &dynamic.RouterTLSConfig{
								CertResolver: "traefik-hub",
							},
						},
					},
				},
			},
			expectedTLSCfg: &dynamic.TLSConfiguration{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			traefikManager := traefikManagerMock{
				setTLSConfig: func(cfg *dynamic.TLSConfiguration) {
					assert.Equal(t, &dynamic.TLSConfiguration{Certificates: []*tls.CertAndStores{}}, cfg,
						"SetTLSConfig should be called with empty TLS configuration")
				},
			}

			certClient := CertClientMock{obtain: func(domains []string) (Certificate, error) {
				assert.Fail(t, "Obtain should not be called")
				return Certificate{}, nil
			}}

			tlsConfigBuilder := NewTLSConfigBuilder(traefikManager, certClient)
			err := tlsConfigBuilder.ObtainCertificates(test.cfg)
			require.NoError(t, err)
		})
	}
}

func TestTLSConfigBuilder_ObtainCertificates(t *testing.T) {
	now := time.Now()

	var got *dynamic.TLSConfiguration
	traefikManager := traefikManagerMock{
		setTLSConfig: func(cfg *dynamic.TLSConfiguration) {
			got = cfg
		},
	}

	var callCount int
	certClient := CertClientMock{obtain: func(domains []string) (Certificate, error) {
		// Should be called only for an unknown domain list.
		assert.Equal(t, []string{"bar", "foo"}, domains)
		callCount++

		return Certificate{
			Certificate: []byte("foocert"),
			PrivateKey:  []byte("fookey"),
			Domains:     []string{"bar", "foo"},
			NotAfter:    now,
		}, nil
	}}

	tlsConfigBuilder := NewTLSConfigBuilder(traefikManager, certClient)
	tlsConfigBuilder.certs["example.com,example.foo.com"] = Certificate{
		Certificate: []byte("examplecert"),
		PrivateKey:  []byte("examplekey"),
		Domains:     []string{"example.com", "example.foo.com"},
		NotAfter:    now,
	}

	cfg := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"websecure"},
					Service:     "foo",
					Rule:        "Host(`foo`)",
					TLS: &dynamic.RouterTLSConfig{
						CertResolver: "traefik-hub",
						Domains: []types.Domain{
							{
								Main: "foo",
								SANs: []string{"foo", "bar"},
							},
						},
					},
				},
				"bar": {
					EntryPoints: []string{"websecure"},
					Service:     "bar",
					Rule:        "Host(`bar`)",
					TLS: &dynamic.RouterTLSConfig{
						CertResolver: "traefik-hub",
						Domains: []types.Domain{
							{
								Main: "bar",
								SANs: []string{"bar", "foo"},
							},
						},
					},
				},
				"example": {
					EntryPoints: []string{"websecure"},
					Service:     "example",
					Rule:        "Host(`example.com`)",
					TLS: &dynamic.RouterTLSConfig{
						CertResolver: "traefik-hub",
						Domains: []types.Domain{
							{
								Main: "example.com",
								SANs: []string{"example.com", "example.foo.com"},
							},
						},
					},
				},
			},
		},
	}

	err := tlsConfigBuilder.ObtainCertificates(cfg)
	require.NoError(t, err)

	expected := []*tls.CertAndStores{
		{
			Certificate: tls.Certificate{
				CertFile: "foocert",
				KeyFile:  "fookey",
			},
		},
		{
			Certificate: tls.Certificate{
				CertFile: "examplecert",
				KeyFile:  "examplekey",
			},
		},
	}

	// Hacky way of making sure both slices have same content regardless of the order.
	assert.Len(t, got.Certificates, 2)
	assert.Subset(t, got.Certificates, expected)

	assert.Equal(t, 1, callCount)
}

func TestTLSConfigBuilder_ObtainCertificates_WithoutDomainsWithHostRule(t *testing.T) {
	now := time.Now()

	var got *dynamic.TLSConfiguration
	traefikManager := traefikManagerMock{
		setTLSConfig: func(cfg *dynamic.TLSConfiguration) {
			got = cfg
		},
	}

	var callCount int
	certClient := CertClientMock{obtain: func(domains []string) (Certificate, error) {
		// Should be called only for an unknown domain list.
		assert.Equal(t, []string{"bar", "foo"}, domains)
		callCount++

		return Certificate{
			Certificate: []byte("foocert"),
			PrivateKey:  []byte("fookey"),
			Domains:     []string{"foo", "bar"},
			NotAfter:    now,
		}, nil
	}}

	tlsConfigBuilder := NewTLSConfigBuilder(traefikManager, certClient)
	tlsConfigBuilder.certs["example.com,example.foo.com"] = Certificate{
		Certificate: []byte("examplecert"),
		PrivateKey:  []byte("examplekey"),
		Domains:     []string{"example.com", "example.foo.com"},
		NotAfter:    now,
	}

	cfg := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"websecure"},
					Service:     "foo",
					Rule:        "Host(`foo`) || Host(`bar`)",
					TLS: &dynamic.RouterTLSConfig{
						CertResolver: "traefik-hub",
					},
				},
				"example": {
					EntryPoints: []string{"websecure"},
					Service:     "example",
					Rule:        "Host(`example.com`) || Host(`example.foo.com`)",
					TLS: &dynamic.RouterTLSConfig{
						CertResolver: "traefik-hub",
					},
				},
			},
		},
	}

	err := tlsConfigBuilder.ObtainCertificates(cfg)
	require.NoError(t, err)

	expected := []*tls.CertAndStores{
		{
			Certificate: tls.Certificate{
				CertFile: "foocert",
				KeyFile:  "fookey",
			},
		},
		{
			Certificate: tls.Certificate{
				CertFile: "examplecert",
				KeyFile:  "examplekey",
			},
		},
	}

	// Hacky way of making sure both slices have same content regardless of the order.
	assert.Len(t, got.Certificates, 2)
	assert.Subset(t, got.Certificates, expected)

	assert.Equal(t, 1, callCount)
}

func TestTLSConfigBuilder_ObtainCertificates_CertClientError(t *testing.T) {
	cfg := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers: map[string]*dynamic.Router{
				"foo": {
					EntryPoints: []string{"websecure"},
					Service:     "foo",
					Rule:        "Host(`foo`)",
					TLS: &dynamic.RouterTLSConfig{
						CertResolver: "traefik-hub",
						Domains: []types.Domain{
							{
								Main: "foo",
								SANs: []string{"foo", "bar"},
							},
						},
					},
				},
				"example": {
					EntryPoints: []string{"websecure"},
					Service:     "example",
					Rule:        "Host(`example.com`)",
					TLS: &dynamic.RouterTLSConfig{
						CertResolver: "traefik-hub",
						Domains: []types.Domain{
							{
								Main: "example.com",
								SANs: []string{"example.com", "example.foo.com"},
							},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		desc        string
		clientError error
		mustRetry   bool
		certs       map[string]Certificate
	}{
		{
			desc:        "Generic error during certificates.Obtain without cert in cache",
			clientError: errors.New("boom"),
			mustRetry:   true,
		},
		{
			desc:        "Pending error during certificates.Obtain without cert in cache",
			clientError: ErrCertIssuancePending,
			mustRetry:   true,
		},
		{
			desc:        "Client error with certificates in cache",
			clientError: errors.New("boom"),
			mustRetry:   false,
			certs: map[string]Certificate{
				"example.com,example.foo.com": {
					Certificate: []byte("examplecert"),
					PrivateKey:  []byte("examplekey"),
					Domains:     []string{"example.com", "example.foo.com"},
					NotAfter:    time.Now(),
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var got *dynamic.TLSConfiguration
			traefikManager := traefikManagerMock{
				setTLSConfig: func(cfg *dynamic.TLSConfiguration) {
					if len(test.certs) == 0 {
						assert.Equal(t, &dynamic.TLSConfiguration{Certificates: []*tls.CertAndStores{}}, cfg,
							"SetTLSConfig should be called with empty TLS configuration")
					}

					got = cfg
				},
			}

			certClient := CertClientMock{obtain: func(domains []string) (Certificate, error) {
				return Certificate{}, test.clientError
			}}

			tlsConfigBuilder := NewTLSConfigBuilder(traefikManager, certClient)
			if len(test.certs) > 0 {
				tlsConfigBuilder.certs = test.certs
			}

			err := tlsConfigBuilder.ObtainCertificates(cfg)
			if test.mustRetry {
				assert.ErrorIs(t, err, ErrMustRetry)
			}

			if len(test.certs) > 0 {
				expected := &dynamic.TLSConfiguration{
					Certificates: []*tls.CertAndStores{
						{
							Certificate: tls.Certificate{
								CertFile: "examplecert",
								KeyFile:  "examplekey",
							},
						},
					},
				}
				assert.Equal(t, expected, got)
			}
		})
	}
}

func TestTLSConfigBuilder_renewExpiringCertificates(t *testing.T) {
	now := time.Now()

	tests := []struct {
		desc      string
		acmeCerts map[string]Certificate
		expected  *dynamic.TLSConfiguration
	}{
		{
			desc: "nothing to renew",
			acmeCerts: map[string]Certificate{
				"example.com,example.foo.com": {
					Certificate: []byte("foocert"),
					PrivateKey:  []byte("fookey"),
					Domains:     []string{"foo", "foo.bar"},
					NotAfter:    now.Add(31 * 24 * time.Hour),
				},
			},
		},
		{
			desc: "Renew cert",
			acmeCerts: map[string]Certificate{
				"example.com,example.foo.com": {
					Certificate: []byte("foocert"),
					PrivateKey:  []byte("fookey"),
					Domains:     []string{"foo", "foo.bar"},
					NotAfter:    now.Add(-31 * 24 * time.Hour),
				},
			},
			expected: &dynamic.TLSConfiguration{
				Certificates: []*tls.CertAndStores{
					{
						Certificate: tls.Certificate{
							CertFile: "foocert",
							KeyFile:  "fookey",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var got *dynamic.TLSConfiguration
			traefikManager := traefikManagerMock{
				setTLSConfig: func(cfg *dynamic.TLSConfiguration) {
					if test.expected == nil {
						assert.Fail(t, "setTLSConfig should not be called")
					}

					got = cfg
				},
			}

			certClient := CertClientMock{obtain: func(domains []string) (Certificate, error) {
				cert, ok := test.acmeCerts[strings.Join(domains, ",")]
				require.True(t, ok)
				cert.NotAfter = now.Add(31 * 24 * time.Hour)

				return cert, nil
			}}

			tlsConfigBuilder := NewTLSConfigBuilder(traefikManager, certClient)
			if test.acmeCerts != nil {
				tlsConfigBuilder.certs = test.acmeCerts
			}

			tlsConfigBuilder.renewExpiringCertificates()
			if test.expected != nil {
				assert.Equal(t, test.expected, got)
				notAfter := test.acmeCerts["example.com,example.foo.com"].NotAfter
				notAfter.After(now.Add(30 * 24 * time.Hour))
			}
		})
	}
}
