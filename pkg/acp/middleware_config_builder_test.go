package acp

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/neo-agent/pkg/acp/basicauth"
	"github.com/traefik/neo-agent/pkg/acp/digestauth"
	"github.com/traefik/neo-agent/pkg/acp/jwt"
)

type traefikManagerMock struct {
	setMiddlewaresConfig func(map[string]*dynamic.Middleware)
}

func (m traefikManagerMock) SetMiddlewaresConfig(mdlwrs map[string]*dynamic.Middleware) {
	m.setMiddlewaresConfig(mdlwrs)
}

func TestMiddlewareConfigBuilder_UpdateConfig(t *testing.T) {
	const reachableAddr = "127.0.0.1:1234"

	tests := []struct {
		desc     string
		acps     map[string]Config
		expected map[string]*dynamic.Middleware
	}{
		{
			desc: "JWT ACP",
			acps: map[string]Config{
				"jwtTest": {
					JWT: &jwt.Config{
						ForwardHeaders: map[string]string{
							"Foo": "test",
							"Bar": "test2",
						},
						StripAuthorizationHeader: true,
					},
				},
			},
			expected: map[string]*dynamic.Middleware{
				"jwtTest": {
					ForwardAuth: &dynamic.ForwardAuth{
						Address:             fmt.Sprintf("%s/%s", reachableAddr, "jwtTest"),
						AuthResponseHeaders: []string{"Foo", "Bar", "Authorization"},
					},
				},
			},
		},
		{
			desc: "BasicAuth ACP",
			acps: map[string]Config{
				"basicAuthTest": {
					BasicAuth: &basicauth.Config{
						StripAuthorizationHeader: true,
						ForwardUsernameHeader:    "Foo",
					},
				},
			},
			expected: map[string]*dynamic.Middleware{
				"basicAuthTest": {
					ForwardAuth: &dynamic.ForwardAuth{
						Address:             fmt.Sprintf("%s/%s", reachableAddr, "basicAuthTest"),
						AuthResponseHeaders: []string{"Foo", "Authorization"},
					},
				},
			},
		},
		{
			desc: "DigestAuth ACP",
			acps: map[string]Config{
				"digestAuthTest": {
					DigestAuth: &digestauth.Config{
						StripAuthorizationHeader: true,
						ForwardUsernameHeader:    "Bar",
					},
				},
			},
			expected: map[string]*dynamic.Middleware{
				"digestAuthTest": {
					ForwardAuth: &dynamic.ForwardAuth{
						Address:             fmt.Sprintf("%s/%s", reachableAddr, "digestAuthTest"),
						AuthResponseHeaders: []string{"Bar", "Authorization"},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			var got map[string]*dynamic.Middleware
			traefikManager := traefikManagerMock{
				setMiddlewaresConfig: func(m map[string]*dynamic.Middleware) {
					got = m
				},
			}

			builder := NewMiddlewareConfigBuilder(traefikManager, reachableAddr)
			err := builder.UpdateConfig(test.acps)
			require.NoError(t, err)

			for k := range got {
				sort.Strings(got[k].ForwardAuth.AuthResponseHeaders)
			}

			for k := range test.expected {
				sort.Strings(test.expected[k].ForwardAuth.AuthResponseHeaders)
			}

			assert.Equal(t, test.expected, got)
		})
	}
}
