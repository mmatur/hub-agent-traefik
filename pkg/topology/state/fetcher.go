package state

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/types"
	"github.com/traefik/neo-agent/pkg/acp"
	"github.com/traefik/neo-agent/pkg/traefik"
)

// Fetcher fetches Traefik dynamic configuration and converts them into a filtered and simplified state.
type Fetcher struct {
	clusterID      string
	traefikManager *traefik.Manager

	acpsMu sync.RWMutex
	acps   map[string]acp.Config
}

// NewFetcher returns a new Fetcher.
func NewFetcher(clusterID string, c *traefik.Manager) *Fetcher {
	return &Fetcher{
		clusterID:      clusterID,
		traefikManager: c,
		acps:           map[string]acp.Config{},
	}
}

// FetchState assembles a cluster state from Traefik dynamic configuration.
func (f *Fetcher) FetchState(ctx context.Context) (*Cluster, error) {
	cfg, err := f.traefikManager.GetDynamic(ctx)
	if err != nil {
		return nil, fmt.Errorf("get dynamic configuration: %w", err)
	}

	cluster := &Cluster{
		ID: f.clusterID,
		IngressControllers: map[string]*IngressController{
			"traefik@traefik": {
				Name: "traefik@traefik",
				Kind: "Multiplatform",
				Type: "traefik",
			},
		},
	}

	pluginName := f.traefikManager.PluginName()

	f.acpsMu.RLock()
	cluster.AccessControlPolicies = make(map[string]*AccessControlPolicy)
	for name, policy := range f.acps {
		policy := policy
		cluster.AccessControlPolicies[name+"@"+pluginName] = f.buildACP(name+"@"+pluginName, &policy)
	}
	f.acpsMu.RUnlock()

	cluster.Overview = Overview{
		IngressControllerTypes: []string{"traefik"},
	}

	if cfg.HTTP == nil {
		return cluster, nil
	}

	cluster.IngressRoutes = make(map[string]*IngressRoute)
	for name, router := range cfg.HTTP.Routers {
		ingressRoute := f.buildIngressRoute(name, router, cluster.AccessControlPolicies)
		if ingressRoute == nil {
			continue
		}

		cluster.IngressRoutes[name] = ingressRoute
	}

	cluster.Services = make(map[string]*Service)
	for name, svc := range cfg.HTTP.Services {
		var t string
		switch {
		case svc.Weighted != nil:
			t = "TraefikWRR"
		case svc.Mirroring != nil:
			t = "TraefikMirroring"
		case svc.LoadBalancer != nil:
			t = "TraefikLoadBalancer"
		}
		cluster.Services[name] = &Service{
			Name:      name,
			Type:      t,
			ClusterID: f.clusterID,
		}
	}

	cluster.Overview.IngressCount = len(cluster.IngressRoutes)
	cluster.Overview.ServiceCount = len(cluster.Services)

	return cluster, nil
}

func (f *Fetcher) buildIngressRoute(name string, router *dynamic.Router, acps map[string]*AccessControlPolicy) *IngressRoute {
	service, err := serviceName(router.Service, name)
	if err != nil {
		log.Error().Err(err).Msg("Generate service name")
		return nil
	}

	ingressRoute := &IngressRoute{
		ResourceMeta: ResourceMeta{Kind: "Router", Name: name},
		IngressMeta:  IngressMeta{ClusterID: f.clusterID, ControllerType: "traefik"},
		Routes:       buildRoutes(router, service),
		Services:     []string{service},
	}

	if router.TLS != nil {
		ingressRoute.TLS = &IngressRouteTLS{
			Domains: buildDomains(router.TLS),
			Options: &TLSOptionRef{Name: router.TLS.Options},
		}
	}

	for _, middleware := range router.Middlewares {
		f.acpsMu.RLock()
		if _, found := acps[middleware]; found {
			if ingressRoute.Annotations == nil {
				ingressRoute.Annotations = make(map[string]string)
			}
			ingressRoute.Annotations["hub.traefik.io/access-control-policy"] = middleware
			f.acpsMu.RUnlock()
			break
		}
		f.acpsMu.RUnlock()
	}

	return ingressRoute
}

// UpdateACP updates ACPs held by the fetcher.
func (f *Fetcher) UpdateACP(cfgs map[string]acp.Config) error {
	f.acpsMu.Lock()
	defer f.acpsMu.Unlock()

	f.acps = cfgs

	return nil
}

func serviceName(rawServiceName, routerName string) (string, error) {
	// If the service name contains a specific provider, we keep it.
	if len(strings.Split(rawServiceName, "@")) > 1 {
		return rawServiceName, nil
	}

	parts := strings.Split(routerName, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected router name format: %s", routerName)
	}

	return rawServiceName + "@" + parts[1], nil
}

func buildDomains(tls *dynamic.RouterTLSConfig) []types.Domain {
	var domains []types.Domain
	for _, domain := range tls.Domains {
		domains = append(domains, types.Domain{
			Main: domain.Main,
			SANs: domain.SANs,
		})
	}

	return domains
}

func buildRoutes(router *dynamic.Router, service string) []Route {
	return []Route{
		{
			Match:    router.Rule,
			Services: []RouteService{{Name: service}},
		},
	}
}

func (f *Fetcher) buildACP(name string, acpCfg *acp.Config) *AccessControlPolicy {
	policy := &AccessControlPolicy{
		Name:      name,
		ClusterID: f.clusterID,
	}

	switch {
	case acpCfg.JWT != nil:
		policy.Method = "jwt"
		policy.JWT = &AccessControlPolicyJWT{
			SigningSecretBase64Encoded: acpCfg.JWT.SigningSecretBase64Encoded,
			PublicKey:                  acpCfg.JWT.PublicKey,
			StripAuthorizationHeader:   acpCfg.JWT.StripAuthorizationHeader,
			ForwardHeaders:             acpCfg.JWT.ForwardHeaders,
			TokenQueryKey:              acpCfg.JWT.TokenQueryKey,
			JWKsFile:                   acpCfg.JWT.JWKsFile.String(),
			JWKsURL:                    acpCfg.JWT.JWKsURL,
			Claims:                     acpCfg.JWT.Claims,
		}

		if acpCfg.JWT.SigningSecret != "" {
			policy.JWT.SigningSecret = "redacted"
		}
	case acpCfg.BasicAuth != nil:
		policy.Method = "basicauth"
		policy.BasicAuth = &AccessControlPolicyBasicAuth{
			Users:                    removePassword(acpCfg.BasicAuth.Users),
			Realm:                    acpCfg.BasicAuth.Realm,
			StripAuthorizationHeader: acpCfg.BasicAuth.StripAuthorizationHeader,
			ForwardUsernameHeader:    acpCfg.BasicAuth.ForwardUsernameHeader,
		}
	case acpCfg.DigestAuth != nil:
		policy.Method = "digestauth"
		policy.DigestAuth = &AccessControlPolicyDigestAuth{
			Users:                    removePassword(acpCfg.DigestAuth.Users),
			Realm:                    acpCfg.DigestAuth.Realm,
			StripAuthorizationHeader: acpCfg.DigestAuth.StripAuthorizationHeader,
			ForwardUsernameHeader:    acpCfg.DigestAuth.ForwardUsernameHeader,
		}
	default:
		return nil
	}

	return policy
}

func removePassword(rawUsers []string) string {
	var users []string
	for _, u := range rawUsers {
		parts := strings.Split(u, ":")

		// Digest format: user:realm:secret
		if len(parts) == 3 {
			users = append(users, parts[0]+":"+parts[1]+":redacted")
			continue
		}

		users = append(users, parts[0]+":redacted")
	}

	return strings.Join(users, ",")
}
