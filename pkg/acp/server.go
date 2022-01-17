package acp

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Server serves ACP endpoints.
type Server struct {
	listenAddr string
	handler    *httpHandler
}

// NewServer creates a new ACP Server.
func NewServer(listenAddr string) *Server {
	return &Server{
		listenAddr: listenAddr,
		handler:    newHTTPHandler(),
	}
}

// UpdateHandler updates auth routes served by the Server.
func (s *Server) UpdateHandler(cfgs map[string]Config) error {
	routes, err := buildRoutes(cfgs)
	if err != nil {
		return fmt.Errorf("build routes: %w", err)
	}

	s.handler.Update(routes)

	return nil
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
		Addr:     s.listenAddr,
		Handler:  mux,
		ErrorLog: stdlog.New(log.Logger.Level(zerolog.DebugLevel), "", 0),
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
	case <-srvDone:
		return errors.New("auth server stopped")
	}

	return nil
}
