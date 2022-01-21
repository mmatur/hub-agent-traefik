package acp

import (
	"math"
	"reflect"
	"sort"
	"strings"

	"github.com/traefik/genconf/dynamic"
)

// Quota applies maxSecuredRoute quota.
type Quota struct {
	traefik         TraefikManager
	maxSecuredRoute int
	acps            []string

	lastCfg map[string]*dynamic.Router
}

// NewQuota returns a new quota instance.
func NewQuota(traefik TraefikManager, maxSecuredRoute int) *Quota {
	return &Quota{
		traefik:         traefik,
		maxSecuredRoute: maxSecuredRoute,
	}
}

// Apply applies maxSecuredRoute quota on dynamic configuration.
func (q *Quota) Apply(cfg *dynamic.Configuration) error {
	if cfg.HTTP == nil {
		q.sendRouters(nil)
		return nil
	}

	pluginName := q.traefik.PluginName()
	securedRoutes := map[string]*dynamic.Router{}
	var rtNames []string
	for rtName, rt := range cfg.HTTP.Routers {
		if !haveACP(rt.Middlewares, q.acps, pluginName) {
			continue
		}

		rtNames = append(rtNames, rtName)
		securedRoutes[rtName] = rt
	}

	if len(rtNames) == 0 {
		q.sendRouters(nil)
		return nil
	}

	// Sort routers to be sure to avoid flaky behavior.
	sort.Strings(rtNames)
	routers := map[string]*dynamic.Router{}
	for i, name := range rtNames {
		if i >= q.maxSecuredRoute {
			rtName, rt := cloneRouter(name, securedRoutes[name])
			routers[rtName] = rt
		}
	}

	q.sendRouters(routers)

	return nil
}

func (q *Quota) sendRouters(routers map[string]*dynamic.Router) {
	if reflect.DeepEqual(q.lastCfg, routers) {
		return
	}

	q.lastCfg = routers
	q.traefik.SetRoutersConfig(routers)
}

func cloneRouter(rtName string, rt *dynamic.Router) (string, *dynamic.Router) {
	parts := strings.Split(rtName, "@")
	svcParts := strings.Split(rt.Service, "@")

	service := rt.Service
	if len(svcParts) == 1 {
		service = svcParts[0] + "@" + parts[1]
	}

	return parts[0], &dynamic.Router{
		EntryPoints: rt.EntryPoints,
		Middlewares: []string{"quota-exceeded"},
		Service:     service,
		Rule:        rt.Rule,
		Priority:    math.MaxInt32 - 1,
		TLS:         rt.TLS,
	}
}

func haveACP(middlewares, acps []string, pluginName string) bool {
	for _, middleware := range middlewares {
		for _, acp := range acps {
			if middleware == acp+"@"+pluginName {
				return true
			}
		}
	}

	return false
}

// UpdateACP updates ACPs.
func (q *Quota) UpdateACP(cfgs map[string]Config) error {
	var acpNames []string
	for acpName := range cfgs {
		acpNames = append(acpNames, acpName)
	}

	q.acps = acpNames

	return nil
}
