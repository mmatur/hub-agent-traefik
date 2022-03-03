package traefik

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
	"github.com/traefik/neo-agent/pkg/certificate"
)

// ProviderName is the name of the Traefik Hub provider.
const ProviderName = "hub"

// Traefik allows pushing dynamic configurations to a Traefik instance.
type Traefik interface {
	GetDynamic(ctx context.Context) (*dynamic.Configuration, error)
	PushDynamic(ctx context.Context, unixNano int64, cfg *dynamic.Configuration) error
	GetProviderState(ctx context.Context) (ProviderState, error)
}

// Manager manages Traefik dynamic configurations.
type Manager struct {
	// dynCfg is the next configuration that will be pushed to Traefik.
	dynCfgMu sync.RWMutex
	dynCfg   *dynamic.Configuration

	// lastTraefikCfg is the last configuration we pulled from Traefik.
	lastTraefikCfg *dynamic.Configuration

	// Accessed atomically.
	lastRefreshUnixNano int64

	refresh      chan struct{}
	syncInterval time.Duration

	traefik Traefik

	updateFuncsMu sync.RWMutex
	updateFuncs   []UpdateFunc
}

// UpdateFunc is a function called when Traefik dynamic configuration is modified.
type UpdateFunc func(cfg *dynamic.Configuration) error

// NewManager returns a new Manager.
func NewManager(ctx context.Context, traefik Traefik) (*Manager, error) {
	return &Manager{
		dynCfg:       emptyDynamicConfiguration(),
		refresh:      make(chan struct{}),
		syncInterval: 15 * time.Second,
		traefik:      traefik,
	}, nil
}

// Run runs the Manager.
func (m *Manager) Run(ctx context.Context) {
	go m.runProviderStateSync(ctx)
	go m.runTraefikDynamicSync(ctx)

	for {
		select {
		case <-m.refresh:
			pushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)

			unixNano := time.Now().UnixNano()

			m.dynCfgMu.RLock()
			if err := m.traefik.PushDynamic(pushCtx, unixNano, m.dynCfg); err != nil {
				m.dynCfgMu.RUnlock()
				log.Error().Err(err).Msg("Unable to push Traefik dynamic configuration")
				cancel()
				atomic.StoreInt64(&m.lastRefreshUnixNano, unixNano)
				continue
			}

			cancel()

			atomic.StoreInt64(&m.lastRefreshUnixNano, unixNano)

			log.Trace().
				Int("middlewares", len(m.dynCfg.HTTP.Middlewares)).
				Int("certificates", len(m.dynCfg.TLS.Certificates)).
				Msg("Pushed Traefik dynamic configuration")

			m.dynCfgMu.RUnlock()

		case <-ctx.Done():
			return
		}
	}
}

// AddUpdateListener adds a listener to the config watcher.
func (m *Manager) AddUpdateListener(listener UpdateFunc) {
	m.updateFuncsMu.Lock()
	m.updateFuncs = append(m.updateFuncs, listener)
	m.updateFuncsMu.Unlock()
}

// GetDynamic returns the dynamic configuration.
func (m *Manager) GetDynamic(ctx context.Context) (*dynamic.Configuration, error) {
	return m.traefik.GetDynamic(ctx)
}

func (m *Manager) runProviderStateSync(ctx context.Context) {
	t := time.NewTicker(m.syncInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			ps, err := m.traefik.GetProviderState(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Unable to get last Hub provider state")
				continue
			}

			curr := atomic.LoadInt64(&m.lastRefreshUnixNano)
			if curr != ps.LastConfigUnixNano {
				log.Info().Int64("want", curr).Int64("have", ps.LastConfigUnixNano).Msg("Traefik configuration is out dated, refreshing it")
				m.refresh <- struct{}{}
			}

		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) runTraefikDynamicSync(ctx context.Context) {
	t := time.NewTicker(m.syncInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			cfg, err := m.traefik.GetDynamic(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Unable to get last Traefik dynamic configuration")
				continue
			}

			if reflect.DeepEqual(cfg, m.lastTraefikCfg) {
				continue
			}

			var errs []error
			for _, fn := range m.updateFuncs {
				if err = fn(cfg); err != nil {
					errs = append(errs, err)
					continue
				}
			}

			if len(errs) > 0 {
				filtered := filterErrMustRetry(errs)
				// Don't log retry errors as they are an expected behavior.
				if len(filtered) > 0 {
					log.Error().Errs("errors", filtered).Msg("Unable to execute Traefik dynamic configuration watcher callbacks")
				}

				continue
			}

			m.lastTraefikCfg = cfg

		case <-ctx.Done():
			return
		}
	}
}

func filterErrMustRetry(errs []error) []error {
	var filtered []error
	for _, err := range errs {
		if errors.Is(err, certificate.ErrMustRetry) {
			continue
		}
		filtered = append(filtered, err)
	}

	return filtered
}

// SetMiddlewaresConfig sets middlewares to be pushed to Traefik.
func (m *Manager) SetMiddlewaresConfig(mdlwrs map[string]*dynamic.Middleware) {
	m.dynCfgMu.Lock()
	m.dynCfg.HTTP.Middlewares = mdlwrs
	m.dynCfgMu.Unlock()

	m.refresh <- struct{}{}
}

// SetRoutersConfig sets routers to be pushed to Traefik.
func (m *Manager) SetRoutersConfig(routers map[string]*dynamic.Router) {
	m.dynCfgMu.Lock()
	m.dynCfg.HTTP.Routers = routers
	m.dynCfgMu.Unlock()

	m.refresh <- struct{}{}
}

// SetTLSConfig sets the TLS configuration to be pushed to Traefik.
func (m *Manager) SetTLSConfig(cfg *dynamic.TLSConfiguration) {
	m.dynCfgMu.Lock()
	m.dynCfg.TLS = cfg
	m.dynCfgMu.Unlock()

	m.refresh <- struct{}{}
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
