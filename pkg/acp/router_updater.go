package acp

import (
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/neo-agent/pkg/traefik"
)

// RouterUpdater updates routers to applies quota & ACPs.
type RouterUpdater struct {
	traefik         TraefikManager
	maxSecuredRoute int

	mu             sync.RWMutex
	acps           []string
	securedRouters map[string]string
	lastDynCfg     *dynamic.Configuration

	lastSendCfgMu sync.RWMutex
	lastSendCfg   map[string]*dynamic.Router
}

// NewRouterUpdater returns a new routerUpdater instance.
func NewRouterUpdater(manager TraefikManager, maxSecuredRoute int) *RouterUpdater {
	return &RouterUpdater{
		traefik:         manager,
		maxSecuredRoute: maxSecuredRoute,
	}
}

// UpdateACP updates ACPs.
func (u *RouterUpdater) UpdateACP(cfgs map[string]Config) error {
	var acpNames []string
	securedRouters := map[string]string{}
	for acpName, config := range cfgs {
		acpNames = append(acpNames, acpName)

		for _, ingress := range config.Ingresses {
			securedRouters[ingress] = acpName
		}
	}

	u.mu.Lock()
	u.acps = acpNames
	u.securedRouters = securedRouters
	u.mu.Unlock()

	u.refresh()

	return nil
}

// UpdateDynamic updates the last known dynamic configuration.
func (u *RouterUpdater) UpdateDynamic(currentCfg *dynamic.Configuration) error {
	u.mu.Lock()
	u.lastDynCfg = currentCfg
	u.mu.Unlock()

	u.refresh()

	return nil
}

func (u *RouterUpdater) refresh() {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if len(u.acps) == 0 {
		u.sendRouters(nil)
		return
	}

	if u.lastDynCfg == nil || u.lastDynCfg.HTTP == nil {
		u.sendRouters(nil)
		return
	}

	securedRoutes := map[string]*dynamic.Router{}
	var rtNames []string
	for rtName, rt := range u.lastDynCfg.HTTP.Routers {
		if !haveACP(rt.Middlewares, u.acps) {
			continue
		}

		rtNames = append(rtNames, rtName)
		securedRoutes[rtName] = rt
	}

	if len(rtNames) == 0 {
		u.sendRouters(u.buildSecuredRouters(u.maxSecuredRoute))
		return
	}

	// Sort routers to be sure to avoid flaky behavior.
	sort.Strings(rtNames)
	routers := map[string]*dynamic.Router{}
	for i, name := range rtNames {
		if i >= u.maxSecuredRoute {
			rtName, rt := cloneRouter(name, securedRoutes[name])
			routers[rtName] = rt
		}
	}

	if len(routers) > 0 {
		u.sendRouters(routers)
		return
	}

	u.sendRouters(u.buildSecuredRouters(u.maxSecuredRoute - len(rtNames)))
}

func (u *RouterUpdater) sendRouters(routers map[string]*dynamic.Router) {
	u.lastSendCfgMu.RLock()
	if reflect.DeepEqual(u.lastSendCfg, routers) {
		u.lastSendCfgMu.RUnlock()
		return
	}
	u.lastSendCfgMu.RUnlock()

	u.lastSendCfgMu.Lock()
	if reflect.DeepEqual(u.lastSendCfg, routers) {
		u.lastSendCfgMu.RUnlock()
		return
	}
	u.lastSendCfg = routers
	u.lastSendCfgMu.Unlock()

	u.traefik.SetRoutersConfig(routers)
}

// UpdateSecuredRouter updates secured routers.
func (u *RouterUpdater) buildSecuredRouters(maxSecuredRoute int) map[string]*dynamic.Router {
	if u.lastDynCfg == nil || maxSecuredRoute < 1 {
		return nil
	}

	securedRouters := map[string]*dynamic.Router{}
	for rtName, rt := range u.lastDynCfg.HTTP.Routers {
		parts := strings.Split(rtName, "@")

		if parts[1] == traefik.ProviderName {
			continue
		}

		acpName, found := u.securedRouters[rtName]
		if !found {
			continue
		}

		parts = strings.Split(rtName, "@")
		svcParts := strings.Split(rt.Service, "@")

		service := rt.Service
		if len(svcParts) == 1 {
			service = svcParts[0] + "@" + parts[1]
		}

		securedRouters[parts[0]+"-"+acpName] = &dynamic.Router{
			EntryPoints: rt.EntryPoints,
			Middlewares: append(rt.Middlewares, acpName),
			Service:     service,
			Rule:        rt.Rule,
			Priority:    math.MaxInt32 - 1,
			TLS:         rt.TLS,
		}

		if len(securedRouters) == maxSecuredRoute {
			return securedRouters
		}
	}

	return securedRouters
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

func haveACP(middlewares, acps []string) bool {
	for _, middleware := range middlewares {
		for _, acp := range acps {
			if middleware == acp+"@"+traefik.ProviderName {
				return true
			}
		}
	}

	return false
}
