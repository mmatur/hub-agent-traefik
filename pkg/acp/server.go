/*
Copyright (C) 2022 Traefik Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package acp

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/acp/basicauth"
	"github.com/traefik/hub-agent-traefik/pkg/acp/jwt"
	"github.com/traefik/hub-agent-traefik/pkg/acp/oidc"
	"github.com/traefik/hub-agent-traefik/pkg/edge"
)

// Server serves ACP endpoints.
type Server struct {
	listenAddr string
	handler    *httpHandler

	key string
}

// NewServer creates a new ACP Server.
func NewServer(listenAddr, key string) *Server {
	return &Server{
		listenAddr: listenAddr,
		handler:    newHTTPHandler(),
		key:        key,
	}
}

// UpdateHandler updates auth routes served by the Server.
func (s *Server) UpdateHandler(ctx context.Context, acps []edge.ACP) {
	s.handler.Update(s.buildRoutes(ctx, acps))
}

// Run runs the ACP auth server.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.Handle("/_live", http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	mux.Handle("/_ready", http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))

	mux.Handle("/", s.handler)

	server := &http.Server{
		Addr:              s.listenAddr,
		Handler:           mux,
		ErrorLog:          stdlog.New(log.Logger.Level(zerolog.DebugLevel), "", 0),
		ReadHeaderTimeout: 2 * time.Second,
	}

	srvDone := make(chan struct{})

	go func() {
		log.Info().Str("addr", s.listenAddr).Msg("Starting auth server")
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Err(err).Msg("Unable to listen and serve auth requests")
		}
		close(srvDone)
	}()

	select {
	case <-ctx.Done():
		gracefulCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		//nolint:contextcheck // False positive.
		if err := server.Shutdown(gracefulCtx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown auth server gracefully")
			if err = server.Close(); err != nil {
				return fmt.Errorf("close auth server: %w", err)
			}
		}

		return nil
	case <-srvDone:
		return errors.New("auth server stopped")
	}
}

func (s *Server) buildRoutes(ctx context.Context, acps []edge.ACP) http.Handler {
	mux := http.NewServeMux()

	for _, acp := range acps {
		path := "/" + acp.Name

		logger := log.With().Str("acp_name", acp.Name).Str("acp_type", getACPType(acp)).Logger()

		route, err := buildRoute(ctx, acp, s.key)
		if err != nil {
			logger.Error().Err(err).Msg("create ACP handler")
			continue
		}

		logger.Debug().Msg("Registering ACP handler")

		mux.Handle(path, route)
	}

	return mux
}

func buildRoute(ctx context.Context, acp edge.ACP, key string) (http.Handler, error) {
	switch {
	case acp.OIDC != nil:
		acp.OIDC.Key = key
		return oidc.NewHandler(ctx, acp.OIDC, acp.Name)

	case acp.OIDCGoogle != nil:
		cfg := acp.OIDCGoogle.Config
		cfg.Issuer = "https://accounts.google.com"
		cfg.Scopes = []string{"email"}
		cfg.Claims = buildClaims(acp.OIDCGoogle.Emails)
		cfg.Key = key

		return oidc.NewHandler(ctx, &cfg, acp.Name)

	case acp.JWT != nil:
		return jwt.NewHandler(acp.JWT, acp.Name)

	case acp.BasicAuth != nil:
		return basicauth.NewHandler(acp.BasicAuth, acp.Name)

	default:
		return nil, errors.New("unknown ACP handler type")
	}
}

func getACPType(acp edge.ACP) string {
	switch {
	case acp.JWT != nil:
		return "JWT"

	case acp.BasicAuth != nil:
		return "Basic Auth"

	case acp.OIDC != nil:
		return "OIDC"

	default:
		return "unknown"
	}
}

// buildClaims builds the claims from the emails.
func buildClaims(emails []string) string {
	var claims []string
	for _, email := range emails {
		claims = append(claims, fmt.Sprintf(`Equals("email",%q)`, email))
	}

	return strings.Join(claims, "||")
}
