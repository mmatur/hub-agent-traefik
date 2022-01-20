package acp

import (
	"errors"
	"fmt"

	"github.com/traefik/genconf/dynamic"
)

// TraefikManager allows updating a TraefikManager with the latest middlewares configuration.
type TraefikManager interface {
	SetMiddlewaresConfig(mdlwrs map[string]*dynamic.Middleware)
}

// MiddlewareConfigBuilder builds Traefik middlewares given ACP configurations.
type MiddlewareConfigBuilder struct {
	traefik                 TraefikManager
	authServerReachableAddr string
}

// NewMiddlewareConfigBuilder returns a new MiddlewareConfigBuilder.
func NewMiddlewareConfigBuilder(traefik TraefikManager, authServerReachableAddr string) *MiddlewareConfigBuilder {
	return &MiddlewareConfigBuilder{
		traefik:                 traefik,
		authServerReachableAddr: authServerReachableAddr,
	}
}

// UpdateConfig updates Traefik with middlewares for the given ACPs.
func (b MiddlewareConfigBuilder) UpdateConfig(cfgs map[string]Config) error {
	middlewares := make(map[string]*dynamic.Middleware)

	for polName, cfg := range cfgs {
		headerToFwd, err := headerToForward(cfg)
		if err != nil {
			return fmt.Errorf("header to forward: %w", err)
		}

		middlewares[polName] = &dynamic.Middleware{
			ForwardAuth: &dynamic.ForwardAuth{
				Address:             fmt.Sprintf("%s/%s", b.authServerReachableAddr, polName),
				AuthResponseHeaders: headerToFwd,
			},
		}
	}

	b.traefik.SetMiddlewaresConfig(middlewares)

	return nil
}

func headerToForward(cfg Config) ([]string, error) {
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
