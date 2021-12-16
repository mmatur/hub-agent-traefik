package acp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/neo-agent/pkg/acp/basicauth"
	"github.com/traefik/neo-agent/pkg/acp/digestauth"
	"github.com/traefik/neo-agent/pkg/acp/jwt"
)

type TraefikClientMock struct {
	pushDynamicCallback func(*dynamic.Configuration) error
}

func (t TraefikClientMock) PushDynamic(ctx context.Context, cfg *dynamic.Configuration) error {
	return t.pushDynamicCallback(cfg)
}

func TestTraefikManager_Update(t *testing.T) {
	const reachableAddr = "127.0.0.1:1234"

	tests := []struct {
		desc     string
		acpCfgs  map[string]*Config
		expected map[string]*dynamic.Middleware
	}{
		{
			desc: "Update from a JWT ACP",
			acpCfgs: map[string]*Config{
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
			desc: "Update from a BasicAuth ACP",
			acpCfgs: map[string]*Config{
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
			desc: "Update from a DigestAuth ACP",
			acpCfgs: map[string]*Config{
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
			var got *dynamic.Configuration
			traefikClient := TraefikClientMock{pushDynamicCallback: func(configuration *dynamic.Configuration) error {
				got = configuration
				return nil
			}}

			traefikManager := NewTraefikManager(traefikClient, reachableAddr)
			err := traefikManager.UpdateMiddlewares(context.Background(), test.acpCfgs)
			require.NoError(t, err)

			expected := emptyDynamicConfiguration()
			expected.HTTP.Middlewares = test.expected
			assert.Equal(t, expected, got)
		})
	}
}

func TestTraefikManager_UpdateError(t *testing.T) {
	traefikClient := TraefikClientMock{
		pushDynamicCallback: func(configuration *dynamic.Configuration) error {
			return errors.New("expect error from update")
		},
	}

	traefikManager := NewTraefikManager(traefikClient, "")
	err := traefikManager.UpdateMiddlewares(context.Background(), nil)
	assert.Error(t, err)
}
