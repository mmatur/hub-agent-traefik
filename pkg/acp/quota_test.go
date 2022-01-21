package acp

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/traefik/genconf/dynamic"
)

func TestQuota_Apply(t *testing.T) {
	var gotRouter map[string]*dynamic.Router

	dyncCfg := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers: map[string]*dynamic.Router{
				"rt@docker": {
					EntryPoints: []string{"entrypoint"},
					Service:     "service",
					Rule:        "Host(`whoami`)",
					TLS: &dynamic.RouterTLSConfig{
						Options: "TLSOption",
					},
				},
				"rtSecured@docker": {
					EntryPoints: []string{"entrypoint"},
					Middlewares: []string{"acp@plugin-name"},
					Service:     "service",
					Rule:        "Host(`whoami`)",
					TLS: &dynamic.RouterTLSConfig{
						Options: "TLSOption",
					},
				},
				"zrtSecured@docker": {
					EntryPoints: []string{"entrypoint"},
					Middlewares: []string{"acp2@plugin-name"},
					Service:     "service@file",
					Rule:        "Host(`whoami2`)",
					TLS: &dynamic.RouterTLSConfig{
						Options: "TLSOption",
					},
				},
				"zrtSecuredBis@docker": {
					EntryPoints: []string{"entrypoint"},
					Middlewares: []string{"acp2@plugin-name"},
					Service:     "service",
					Rule:        "Host(`whoamiBis`)",
					TLS: &dynamic.RouterTLSConfig{
						Options: "TLSOption",
					},
				},
			},
		},
	}

	wantRouter := map[string]*dynamic.Router{
		"zrtSecured": {
			EntryPoints: []string{"entrypoint"},
			Middlewares: []string{"quota-exceeded"},
			Service:     "service@file",
			Priority:    math.MaxInt32 - 1,
			Rule:        "Host(`whoami2`)",
			TLS: &dynamic.RouterTLSConfig{
				Options: "TLSOption",
			},
		},
		"zrtSecuredBis": {
			EntryPoints: []string{"entrypoint"},
			Middlewares: []string{"quota-exceeded"},
			Service:     "service@docker",
			Priority:    math.MaxInt32 - 1,
			Rule:        "Host(`whoamiBis`)",
			TLS: &dynamic.RouterTLSConfig{
				Options: "TLSOption",
			},
		},
	}

	var callCountSetRoutersConfig int
	traefik := traefikManagerMock{
		setRoutersConfig: func(rts map[string]*dynamic.Router) {
			callCountSetRoutersConfig++

			gotRouter = rts
		},
		pluginName: func() string {
			return "plugin-name"
		},
	}

	q := NewQuota(traefik, 1)
	err := q.UpdateACP(map[string]Config{
		"acp":  {},
		"acp2": {},
	})
	assert.NoError(t, err)

	err = q.Apply(dyncCfg)
	assert.NoError(t, err)

	assert.Equal(t, wantRouter, gotRouter)
	assert.Equal(t, 1, callCountSetRoutersConfig)
}
