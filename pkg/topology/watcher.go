package topology

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/neo-agent/pkg/topology/state"
	"github.com/traefik/neo-agent/pkg/topology/store"
)

// Watcher is a process from the Hub agent that watches the topology for changes and
// stores them over time to make them accessible from the SaaS.
type Watcher struct {
	fetcher *state.Fetcher
	store   *store.Store
}

// NewWatcher instantiates a new watcher that uses a fetcher to periodically get the Traefik Runtime configuration state and a store to write it.
func NewWatcher(f *state.Fetcher, s *store.Store) *Watcher {
	return &Watcher{
		fetcher: f,
		store:   s,
	}
}

// Start runs the watcher process.
func (w *Watcher) Start(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s, err := w.fetcher.FetchState(ctx)
			if err != nil {
				log.Error().Err(err).Msg("create state")
				continue
			}

			if err = w.store.Write(ctx, s); err != nil {
				log.Error().Err(err).Msg("commit cluster state changes")
			}
		}
	}
}
