package acp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/neo-agent/pkg/acp/basicauth"
	"github.com/traefik/neo-agent/pkg/acp/digestauth"
	"github.com/traefik/neo-agent/pkg/acp/jwt"
)

// UpdateFunc is a function called when ACP are modified.
type UpdateFunc func(cfgs map[string]Config) error

// Watcher watches access control policy resources and calls an UpdateFunc when there is a change.
type Watcher struct {
	refreshInterval time.Duration
	client          *Client

	updateFuncs []UpdateFunc
}

// NewWatcher returns a new watcher to track ACP resources.
func NewWatcher(client *Client, funcs ...UpdateFunc) *Watcher {
	return &Watcher{
		refreshInterval: 30 * time.Second,
		client:          client,
		updateFuncs:     funcs,
	}
}

// Run runs the watcher.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.refreshInterval)
	defer t.Stop()

	var previous map[string]Config

	log.Info().Msg("Starting ACP watcher")

	for {
		select {
		case <-t.C:
			configs, err := w.client.GetACPs(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read ACP")
				continue
			}

			if reflect.DeepEqual(previous, configs) {
				continue
			}

			log.Debug().Msg("Executing ACP watcher callbacks")

			var errs []error
			for _, fn := range w.updateFuncs {
				if err = fn(configs); err != nil {
					errs = append(errs, err)
					continue
				}
			}

			if len(errs) > 0 {
				log.Error().Errs("errors", errs).Msg("Unable to execute ACP watcher callbacks")
				continue
			}

			previous = configs

		case <-ctx.Done():
			return
		}
	}
}

func buildRoutes(cfgs map[string]Config) (http.Handler, error) {
	mux := http.NewServeMux()

	for name, cfg := range cfgs {
		switch {
		case cfg.JWT != nil:
			jwtHandler, err := jwt.NewHandler(cfg.JWT, name)
			if err != nil {
				return nil, fmt.Errorf("create %q JWT ACP handler: %w", name, err)
			}

			path := "/" + name

			log.Debug().Str("acp_name", name).Str("path", path).Msg("Registering JWT ACP handler")

			mux.Handle(path, jwtHandler)

		case cfg.BasicAuth != nil:
			h, err := basicauth.NewHandler(cfg.BasicAuth, name)
			if err != nil {
				return nil, fmt.Errorf("create %q basic auth ACP handler: %w", name, err)
			}
			path := "/" + name
			log.Debug().Str("acp_name", name).Str("path", path).Msg("Registering basic auth ACP handler")
			mux.Handle(path, h)

		case cfg.DigestAuth != nil:
			h, err := digestauth.NewHandler(cfg.DigestAuth, name)
			if err != nil {
				return nil, fmt.Errorf("create %q digest auth ACP handler: %w", name, err)
			}
			path := "/" + name
			log.Debug().Str("acp_name", name).Str("path", path).Msg("Registering digest auth ACP handler")
			mux.Handle(path, h)

		default:
			return nil, errors.New("unknown ACP handler type")
		}
	}

	return mux, nil
}
