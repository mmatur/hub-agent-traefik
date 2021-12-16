package acp

import (
	"context"
	"errors"
	"fmt"

	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
)

// Traefik allows pushing dynamic configurations to a Traefik instance.
type Traefik interface {
	PushDynamic(ctx context.Context, cfg *dynamic.Configuration) error
}

// TraefikManager manages a Traefik instance by pushing dynamic configurations to enforces ACPs.
type TraefikManager struct {
	traefik                 Traefik
	authServerReachableAddr string
}

// NewTraefikManager returns a new TraefikManager.
func NewTraefikManager(traefik Traefik, authServerReachableAddr string) *TraefikManager {
	return &TraefikManager{
		traefik:                 traefik,
		authServerReachableAddr: authServerReachableAddr,
	}
}

// UpdateMiddlewares updates Traefik with middlewares for the given ACPs.
func (m TraefikManager) UpdateMiddlewares(ctx context.Context, cfgs map[string]*Config) error {
	newCfg := emptyDynamicConfiguration()

	for polName, cfg := range cfgs {
		headerToFwd, err := headerToForward(cfg)
		if err != nil {
			return fmt.Errorf("header to forward: %w", err)
		}

		newCfg.HTTP.Middlewares[polName] = &dynamic.Middleware{
			ForwardAuth: &dynamic.ForwardAuth{
				Address:             fmt.Sprintf("%s/%s", m.authServerReachableAddr, polName),
				AuthResponseHeaders: headerToFwd,
			},
		}
	}

	if err := m.traefik.PushDynamic(ctx, newCfg); err != nil {
		return fmt.Errorf("push dynamic configuration: %w", err)
	}

	return nil
}

func headerToForward(cfg *Config) ([]string, error) {
	var headerToFwd []string

	switch {
	case cfg.JWT != nil:
		for headerName := range cfg.JWT.ForwardHeaders {
			headerToFwd = append(headerToFwd, headerName)
		}
		if cfg.JWT.StripAuthorizationHeader {
			headerToFwd = append(headerToFwd, "Authorization")
		}

	case cfg.BasicAuth != nil:
		if headerName := cfg.BasicAuth.ForwardUsernameHeader; headerName != "" {
			headerToFwd = append(headerToFwd, headerName)
		}
		if cfg.BasicAuth.StripAuthorizationHeader {
			headerToFwd = append(headerToFwd, "Authorization")
		}

	case cfg.DigestAuth != nil:
		if headerName := cfg.DigestAuth.ForwardUsernameHeader; headerName != "" {
			headerToFwd = append(headerToFwd, headerName)
		}
		if cfg.DigestAuth.StripAuthorizationHeader {
			headerToFwd = append(headerToFwd, "Authorization")
		}

	default:
		return nil, errors.New("unsupported ACP type")
	}

	return headerToFwd, nil
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
