package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
)

type traefikManagerMock struct {
	setTLSConfig func(cfg *dynamic.TLSConfiguration)
}

func (m traefikManagerMock) SetTLSConfig(cfg *dynamic.TLSConfiguration) {
	m.setTLSConfig(cfg)
}

func TestTLSConfigBuilder_UpdateConfig(t *testing.T) {
	tests := []struct {
		desc     string
		certs    []Certificate
		expected *dynamic.TLSConfiguration
	}{
		{
			desc: "one certificate",
			certs: []Certificate{
				{
					Cert: "cert1",
					Key:  "key1",
				},
			},
			expected: &dynamic.TLSConfiguration{
				Certificates: []*tls.CertAndStores{
					{
						Certificate: tls.Certificate{
							CertFile: "cert1",
							KeyFile:  "key1",
						},
					},
				},
			},
		},
		{
			desc: "two certificates",
			certs: []Certificate{
				{
					Cert: "cert1",
					Key:  "key1",
				},
				{
					Cert: "cert2",
					Key:  "key2",
				},
			},
			expected: &dynamic.TLSConfiguration{
				Certificates: []*tls.CertAndStores{
					{
						Certificate: tls.Certificate{
							CertFile: "cert1",
							KeyFile:  "key1",
						},
					},
					{
						Certificate: tls.Certificate{
							CertFile: "cert2",
							KeyFile:  "key2",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			var got *dynamic.TLSConfiguration
			traefikManager := traefikManagerMock{
				setTLSConfig: func(cfg *dynamic.TLSConfiguration) {
					got = cfg
				},
			}

			builder := NewTLSConfigBuilder(traefikManager)
			err := builder.UpdateConfig(test.certs)
			require.NoError(t, err)

			assert.Equal(t, test.expected, got)
		})
	}
}
