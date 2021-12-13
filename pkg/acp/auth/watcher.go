package auth

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/neo-agent/pkg/acp"
	"github.com/traefik/neo-agent/pkg/acp/basicauth"
	"github.com/traefik/neo-agent/pkg/acp/digestauth"
	"github.com/traefik/neo-agent/pkg/acp/jwt"
	"gopkg.in/yaml.v3"
)

// Watcher watches access control policy resources and builds configurations out of them.
type Watcher struct {
	configs  map[string]*acp.Config
	previous map[string]*acp.Config

	acpDir          string
	refreshInterval time.Duration

	switcher *HTTPHandlerSwitcher
}

// NewWatcher returns a new watcher to track ACP resources.
func NewWatcher(switcher *HTTPHandlerSwitcher, acpDir string) *Watcher {
	return &Watcher{
		refreshInterval: 5 * time.Second,
		acpDir:          acpDir,
		configs:         make(map[string]*acp.Config),
		switcher:        switcher,
	}
}

// Run runs the watcher.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.refreshInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			var err error
			w.configs, err = readACPDir(w.acpDir)
			if err != nil {
				log.Error().Err(err).Str("directory", w.acpDir).Msg("Unable to read ACP from directory")
				continue
			}

			if reflect.DeepEqual(w.previous, w.configs) {
				continue
			}

			cfgs := make(map[string]*acp.Config, len(w.configs))
			for k, v := range w.configs {
				cfgs[k] = v
			}

			w.previous = cfgs

			log.Debug().Msg("Refreshing ACP handlers")

			routes, err := buildRoutes(cfgs)
			if err != nil {
				log.Error().Err(err).Msg("Unable to switch ACP handlers")
				continue
			}

			w.switcher.UpdateHandler(routes)

		case <-ctx.Done():
			return
		}
	}
}

func readACPDir(dir string) (map[string]*acp.Config, error) {
	cfgs := make(map[string]*acp.Config)

	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			return nil
		}

		acpName := filepath.Base(strings.TrimSuffix(path, filepath.Ext(path)))
		if _, ok := cfgs[acpName]; ok {
			return fmt.Errorf("multiple ACP named %q defined", acpName)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read file %q: %w", path, err)
		}

		var cfg acp.Config
		if err = yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("deserialize ACP configuration: %w", err)
		}

		cfgs[acpName] = &cfg

		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return cfgs, nil
}

func buildRoutes(cfgs map[string]*acp.Config) (http.Handler, error) {
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
