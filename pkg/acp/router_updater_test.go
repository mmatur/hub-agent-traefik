package acp

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/traefik/genconf/dynamic"
)

func TestRouterUpdater_updateDynamicAppliesQuota(t *testing.T) {
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
					Middlewares: []string{"acp@hub"},
					Service:     "service",
					Rule:        "Host(`whoami`)",
					TLS: &dynamic.RouterTLSConfig{
						Options: "TLSOption",
					},
				},
				"zrtSecured@docker": {
					EntryPoints: []string{"entrypoint"},
					Middlewares: []string{"acp2@hub"},
					Service:     "service@file",
					Rule:        "Host(`whoami2`)",
					TLS: &dynamic.RouterTLSConfig{
						Options: "TLSOption",
					},
				},
				"zrtSecuredBis@docker": {
					EntryPoints: []string{"entrypoint"},
					Middlewares: []string{"acp2@hub"},
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
	}

	q := NewRouterUpdater(traefik, 1)
	err := q.UpdateACP(map[string]Config{
		"acp":  {},
		"acp2": {},
	})
	assert.NoError(t, err)

	err = q.UpdateDynamic(dyncCfg)
	assert.NoError(t, err)

	assert.Equal(t, wantRouter, gotRouter)
	assert.Equal(t, 1, callCountSetRoutersConfig)
}

func TestRouterUpdater_updateSecuredIngress(t *testing.T) {
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
				"rt-bis@docker": {
					EntryPoints: []string{"entrypoint"},
					Service:     "service@file",
					Rule:        "Host(`whoami`)",
					TLS: &dynamic.RouterTLSConfig{
						Options: "TLSOption",
					},
				},
			},
		},
	}

	wantRouter := map[string]*dynamic.Router{
		"rt-acp": {
			EntryPoints: []string{"entrypoint"},
			Middlewares: []string{"acp"},
			Service:     "service@docker",
			Priority:    math.MaxInt32 - 1,
			Rule:        "Host(`whoami`)",
			TLS: &dynamic.RouterTLSConfig{
				Options: "TLSOption",
			},
		},
		"rt-bis-acp-bis": {
			EntryPoints: []string{"entrypoint"},
			Middlewares: []string{"acp-bis"},
			Service:     "service@file",
			Priority:    math.MaxInt32 - 1,
			Rule:        "Host(`whoami`)",
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
	}

	u := NewRouterUpdater(traefik, 2)
	u.lastDynCfg = dyncCfg
	err := u.UpdateACP(map[string]Config{
		"acp":     {Ingresses: []string{"rt@docker"}},
		"acp-bis": {Ingresses: []string{"rt-bis@docker"}},
	})
	assert.NoError(t, err)

	assert.Equal(t, wantRouter, gotRouter)
	assert.Equal(t, 1, callCountSetRoutersConfig)
}
