package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
	"github.com/traefik/hub-agent-traefik/pkg/certificate"
	"github.com/traefik/hub-agent-traefik/pkg/edge"
	"github.com/traefik/hub-agent-traefik/pkg/traefik"
)

const quotaExceededMiddleware = "quota-exceeded"

const defaultHubTunnelEntrypoint = "traefikhub-tunl"

// EdgeUpdater keep edge ingresses and Traefik configuration synchronized.
type EdgeUpdater struct {
	certClient    *certificate.Client
	traefikClient *traefik.Client
	provider      ProviderWatcher

	authServerReachableAddr string
	catchAllURL             string
	maxSecuredRoute         int
}

// NewEdgeUpdater creates EdgeUpdater.
func NewEdgeUpdater(certClient *certificate.Client, traefikClient *traefik.Client, provider ProviderWatcher, authServerReachableAddr, catchAllURL string, maxSecuredRoute int) *EdgeUpdater {
	return &EdgeUpdater{
		certClient:              certClient,
		traefikClient:           traefikClient,
		provider:                provider,
		authServerReachableAddr: authServerReachableAddr,
		catchAllURL:             catchAllURL,
		maxSecuredRoute:         maxSecuredRoute,
	}
}

// Update updates Traefik configuration from edge ingresses and ACPs.
func (e EdgeUpdater) Update(ctx context.Context, ingresses []edge.Ingress, acps []edge.ACP) error {
	cfg := emptyDynamicConfiguration()

	var err error
	cfg.HTTP.Middlewares, err = e.acpToMiddleware(acps)
	if err != nil {
		return fmt.Errorf("acp to middleware: %w", err)
	}

	err = e.appendEdgeToTraefikCfg(ctx, cfg, ingresses)
	if err != nil {
		return fmt.Errorf("append edge to traefik cfg: %w", err)
	}

	err = e.traefikClient.PushDynamic(ctx, time.Now().UnixNano(), cfg)
	if err != nil {
		return fmt.Errorf("push dynamic: %w", err)
	}

	return nil
}

func (e EdgeUpdater) appendEdgeToTraefikCfg(ctx context.Context, cfg *dynamic.Configuration, edgeIngresses []edge.Ingress) error {
	cert, err := e.certClient.GetCertificate(ctx)
	if err != nil {
		return fmt.Errorf("get certificate: %w", err)
	}

	cfg.TLS.Certificates = append(cfg.TLS.Certificates, &tls.CertAndStores{
		Certificate: tls.Certificate{
			CertFile: string(cert.Certificate),
			KeyFile:  string(cert.PrivateKey),
		},
	})

	cfg.HTTP.Middlewares["strip"] = &dynamic.Middleware{
		StripPrefixRegex: &dynamic.StripPrefixRegex{
			Regex: []string{".*"},
		},
	}

	cfg.HTTP.Middlewares["add"] = &dynamic.Middleware{
		AddPrefix: &dynamic.AddPrefix{
			Prefix: "/edge-ingresses/in-progress",
		},
	}

	cfg.HTTP.Routers["catch-all"] = &dynamic.Router{
		EntryPoints: []string{defaultHubTunnelEntrypoint},
		Middlewares: []string{"strip", "add"},
		Service:     "catch-all",
		Rule:        "PathPrefix(`/`)",
		Priority:    1,
		TLS:         &dynamic.RouterTLSConfig{},
	}

	cfg.HTTP.Services["catch-all"] = &dynamic.Service{
		LoadBalancer: &dynamic.ServersLoadBalancer{
			PassHostHeader: func(v bool) *bool { return &v }(false),
			Servers: []dynamic.Server{
				{URL: e.catchAllURL},
			},
		},
	}

	for _, ingress := range edgeIngresses {
		logger := log.With().Str("workspace_id", ingress.WorkspaceID).
			Str("cluster_id", ingress.ClusterID).
			Str("edge_ingress_id", ingress.ID).
			Str("service_name", ingress.Service.Name).
			Str("service_network", ingress.Service.Network).
			Logger()

		ip, err := e.provider.GetIP(ctx, "/"+ingress.Service.Name, ingress.Service.Network)
		if err != nil {
			logger.Error().Err(err).Msg("unable to get IP")
			continue
		}

		if ip == "" {
			logger.Error().Msg("Unable to get service IP")
			continue
		}

		var middleware []string
		if ingress.ACP != nil {
			middleware = append(middleware, ingress.ACP.Name)
		}

		cfg.HTTP.Routers[ingress.Name] = &dynamic.Router{
			EntryPoints: []string{defaultHubTunnelEntrypoint},
			Middlewares: middleware,
			Service:     ingress.Name,
			Rule:        fmt.Sprintf("Host(`%s`)", ingress.Domain),
			Priority:    60,
			TLS:         &dynamic.RouterTLSConfig{},
		}

		cfg.HTTP.Services[ingress.Name] = &dynamic.Service{
			LoadBalancer: &dynamic.ServersLoadBalancer{
				Servers: []dynamic.Server{
					{URL: "http://" + net.JoinHostPort(ip, strconv.Itoa(ingress.Service.Port))},
				},
			},
		}
	}

	return nil
}

func (e EdgeUpdater) acpToMiddleware(acps []edge.ACP) (map[string]*dynamic.Middleware, error) {
	middlewares := make(map[string]*dynamic.Middleware)

	for _, acp := range acps {
		headerToFwd, err := headerToForward(acp)
		if err != nil {
			return nil, err
		}

		middlewares[acp.Name] = &dynamic.Middleware{
			ForwardAuth: &dynamic.ForwardAuth{
				Address:             fmt.Sprintf("%s/%s", e.authServerReachableAddr, acp.Name),
				AuthResponseHeaders: headerToFwd,
			},
		}
	}

	middlewares[quotaExceededMiddleware] = &dynamic.Middleware{
		IPWhiteList: &dynamic.IPWhiteList{
			SourceRange: []string{"8.8.8.8"},
			IPStrategy: &dynamic.IPStrategy{
				ExcludedIPs: []string{"0.0.0.0/0"},
			},
		},
	}

	return middlewares, nil
}

func emptyDynamicConfiguration() *dynamic.Configuration {
	return &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers:           make(map[string]*dynamic.Router),
			Middlewares:       make(map[string]*dynamic.Middleware),
			Services:          make(map[string]*dynamic.Service),
			ServersTransports: make(map[string]*dynamic.ServersTransport),
		},
		TCP: &dynamic.TCPConfiguration{
			Routers:  make(map[string]*dynamic.TCPRouter),
			Services: make(map[string]*dynamic.TCPService),
		},
		TLS: &dynamic.TLSConfiguration{
			Stores:  make(map[string]tls.Store),
			Options: make(map[string]tls.Options),
		},
		UDP: &dynamic.UDPConfiguration{
			Routers:  make(map[string]*dynamic.UDPRouter),
			Services: make(map[string]*dynamic.UDPService),
		},
	}
}

func headerToForward(acp edge.ACP) ([]string, error) {
	var headerToFwd []string

	switch {
	case acp.JWT != nil:
		for headerName := range acp.JWT.ForwardHeaders {
			headerToFwd = append(headerToFwd, headerName)
		}
		if acp.JWT.StripAuthorizationHeader {
			headerToFwd = append(headerToFwd, "Authorization")
		}

	case acp.BasicAuth != nil:
		if headerName := acp.BasicAuth.ForwardUsernameHeader; headerName != "" {
			headerToFwd = append(headerToFwd, headerName)
		}
		if acp.BasicAuth.StripAuthorizationHeader {
			headerToFwd = append(headerToFwd, "Authorization")
		}

	default:
		return nil, errors.New("unsupported ACP type")
	}

	return headerToFwd, nil
}
