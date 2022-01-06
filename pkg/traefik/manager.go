package traefik

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
)

// Traefik allows pushing dynamic configurations to a Traefik instance.
type Traefik interface {
	GetDynamic(ctx context.Context) (*dynamic.Configuration, error)
	PushDynamic(ctx context.Context, unixNano int64, cfg *dynamic.Configuration) error
	GetPluginState(ctx context.Context) (PluginState, error)
}

// Manager manages Traefik dynamic configurations.
type Manager struct {
	dynCfgMu sync.RWMutex
	dynCfg   *dynamic.Configuration

	pluginNameMu sync.RWMutex
	pluginName   string
	// Accessed atomically.
	lastRefreshUnixNano int64

	refresh      chan struct{}
	syncInterval time.Duration

	traefik Traefik
}

// NewManager returns a new Manager.
func NewManager(ctx context.Context, traefik Traefik) (*Manager, error) {
	ps, err := traefik.GetPluginState(ctx)
	if err != nil {
		return nil, fmt.Errorf("get plugin state: %w", err)
	}

	return &Manager{
		dynCfg:       emptyDynamicConfiguration(),
		pluginName:   ps.PluginName,
		refresh:      make(chan struct{}),
		syncInterval: 15 * time.Second,
		traefik:      traefik,
	}, nil
}

// Run runs the Manager.
func (m *Manager) Run(ctx context.Context) {
	go m.runPluginStateSync(ctx)

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

// GetDynamic returns the dynamic configuration.
func (m *Manager) GetDynamic(ctx context.Context) (*dynamic.Configuration, error) {
	return m.traefik.GetDynamic(ctx)
}

func (m *Manager) runPluginStateSync(ctx context.Context) {
	t := time.NewTicker(m.syncInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			ps, err := m.traefik.GetPluginState(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Unable to get last Hub plugin state")
				continue
			}

			m.pluginNameMu.Lock()
			m.pluginName = ps.PluginName
			m.pluginNameMu.Unlock()

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

// PluginName returns the current Hub plugin name.
func (m *Manager) PluginName() string {
	m.pluginNameMu.RLock()
	defer m.pluginNameMu.RUnlock()

	return m.pluginName
}

// SetMiddlewaresConfig sets middlewares to be pushed to Traefik.
func (m *Manager) SetMiddlewaresConfig(mdlwrs map[string]*dynamic.Middleware) {
	m.dynCfgMu.Lock()
	defer m.dynCfgMu.Unlock()

	m.dynCfg.HTTP.Middlewares = mdlwrs
	m.refresh <- struct{}{}
}

// SetTLSConfig sets the TLS configuration to be pushed to Traefik.
func (m *Manager) SetTLSConfig(cfg *dynamic.TLSConfiguration) {
	m.dynCfgMu.Lock()
	defer m.dynCfgMu.Unlock()

	m.dynCfg.TLS = cfg
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
