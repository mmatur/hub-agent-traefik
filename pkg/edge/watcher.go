package edge

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// Listener listens the changes of the edge related elements.
type Listener func(context.Context, []Ingress, []ACP) error

// Watcher watches hub agent configuration.
type Watcher struct {
	client   *Client
	interval time.Duration

	listeners []Listener
}

// NewWatcher return a new Watcher.
func NewWatcher(c *Client, interval time.Duration) *Watcher {
	return &Watcher{
		client:   c,
		interval: interval,
	}
}

// AddListener adds a listener.
func (w *Watcher) AddListener(listener Listener) {
	w.listeners = append(w.listeners, listener)
}

// Run runs ConfigWatcher.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()

	if err := w.reload(ctx); err != nil {
		log.Error().Err(err).Msg("Unable to reload hub-agent-traefik configuration")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sigCh:
			if err := w.reload(ctx); err != nil {
				log.Error().Err(err).Msg("Unable to reload hub-agent-traefik configuration after receiving SIGHUP")
			}
		case <-t.C:
			if err := w.reload(ctx); err != nil {
				log.Error().Err(err).Msg("Unable to reload hub-agent-traefik configuration")
			}
		}
	}
}

func (w Watcher) reload(ctx context.Context) error {
	ingresses, err := w.client.GetEdgeIngresses(ctx)
	if err != nil {
		return fmt.Errorf("get edge ingresses: %w", err)
	}

	sort.Slice(ingresses, func(i, j int) bool {
		return ingresses[i].Name < ingresses[j].Name
	})

	acps, err := w.client.GetACPs(ctx)
	if err != nil {
		return fmt.Errorf("get acps: %w", err)
	}

	for _, listener := range w.listeners {
		err = listener(ctx, ingresses, acps)
		if err != nil {
			return fmt.Errorf("apply edge ingresses and acps: %w", err)
		}
	}

	return nil
}
