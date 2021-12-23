package traefik

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
)

// Traefik allows pushing dynamic configurations to a Traefik instance.
type Traefik interface {
	PushDynamic(ctx context.Context, unixNano int64, cfg *dynamic.Configuration) error
	GetLastConfigReceived(ctx context.Context) (int64, error)
}

// Manager manages Traefik dynamic configurations.
type Manager struct {
	dynCfgMu sync.RWMutex
	dynCfg   *dynamic.Configuration

	refresh chan struct{}
	// Accessed atomically.
	lastRefreshUnixNano int64
	syncInterval        time.Duration

	traefik Traefik
}

// NewManager returns a new Manager.
func NewManager(traefik Traefik) *Manager {
	return &Manager{
		dynCfg:       emptyDynamicConfiguration(),
		refresh:      make(chan struct{}),
		syncInterval: 15 * time.Second,
		traefik:      traefik,
	}
}

// Run runs the Manager.
func (m *Manager) Run(ctx context.Context) {
	go m.runConfigSync(ctx)

	for {
		select {
		case <-m.refresh:
			unixNano := time.Now().UnixNano()
			atomic.StoreInt64(&m.lastRefreshUnixNano, unixNano)

			pushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)

			m.dynCfgMu.RLock()
			if err := m.traefik.PushDynamic(pushCtx, unixNano, m.dynCfg); err != nil {
				log.Error().Err(err).Msg("Unable to push Traefik dynamic configuration")
				cancel()
				m.dynCfgMu.RUnlock()
				continue
			}

			cancel()

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

func (m *Manager) runConfigSync(ctx context.Context) {
	t := time.NewTicker(m.syncInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			ts, err := m.traefik.GetLastConfigReceived(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Unable to get last configuration received by Traefik")
				continue
			}

			curr := atomic.LoadInt64(&m.lastRefreshUnixNano)
			if curr != ts {
				log.Info().Int64("want", curr).Int64("have", ts).Msg("Traefik configuration is out dated, refreshing it")
				m.refresh <- struct{}{}
			}

		case <-ctx.Done():
			return
		}
	}
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
