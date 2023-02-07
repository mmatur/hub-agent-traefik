/*
Copyright (C) 2023 Traefik Labs

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

package main

import (
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/logger"
	"github.com/traefik/hub-agent-traefik/pkg/metrics"
	"github.com/traefik/hub-agent-traefik/pkg/platform"
	"github.com/traefik/hub-agent-traefik/pkg/traefik"
)

func newMetrics(token, platformURL string, cfg platform.MetricsConfig, cfgWatcher *platform.ConfigWatcher, traefikClient *traefik.Client) (*metrics.Manager, *metrics.Store, error) {
	rc := retryablehttp.NewClient()
	rc.RetryWaitMin = time.Second
	rc.RetryWaitMax = 10 * time.Second
	rc.RetryMax = 4
	rc.Logger = logger.NewRetryableHTTPWrapper(log.Logger.With().Str("component", "metrics_client").Logger())

	httpClient := rc.StandardClient()

	client, err := metrics.NewClient(httpClient, platformURL, token)
	if err != nil {
		return nil, nil, err
	}

	store := metrics.NewStore()
	scraper := metrics.NewScraper(traefikClient)

	mgr := metrics.NewManager(client, store, scraper)
	mgr.SetConfig(cfg.Interval, cfg.Tables)

	cfgWatcher.AddListener(func(cfg platform.Config) {
		mgr.SetConfig(cfg.Metrics.Interval, cfg.Metrics.Tables)
	})

	return mgr, store, nil
}
