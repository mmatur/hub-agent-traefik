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

package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const scrapeInterval = time.Minute

// Manager orchestrates metrics scraping and sending.
type Manager struct {
	store   *Store
	client  *Client
	scraper *Scraper

	sendMu     sync.Mutex
	sendIntvl  time.Duration
	sendTables []string
}

// NewManager returns a manager.
func NewManager(client *Client, store *Store, scraper *Scraper) *Manager {
	return &Manager{
		store:      store,
		client:     client,
		scraper:    scraper,
		sendIntvl:  time.Minute,
		sendTables: []string{"1m", "10m", "1h", "1d"},
	}
}

// SetConfig updates the configuration of the metrics manager.
func (m *Manager) SetConfig(sendInterval time.Duration, sendTables []string) {
	m.sendMu.Lock()
	defer m.sendMu.Unlock()

	m.sendIntvl = sendInterval
	m.sendTables = sendTables
}

// Run runs the metrics manager. This is a blocking method.
func (m *Manager) Run(ctx context.Context, hubProviderEntrypoint string) error {
	prevData, err := m.client.GetPreviousData(ctx, true)
	if err != nil {
		return err
	}

	for tbl, data := range prevData {
		if err = m.store.Populate(tbl, data); err != nil {
			return fmt.Errorf("unable to populate table: %w", err)
		}
	}

	go m.startScraper(ctx)
	go m.runSender(ctx)

	<-ctx.Done()

	return nil
}

func (m *Manager) runSender(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		case <-time.After(m.getSendInterval()):
			if err := m.send(ctx, m.getSendTables()); err != nil {
				log.Error().Err(err).Msg("Unable to send metrics")
			}
		}
	}
}

func (m *Manager) getSendInterval() time.Duration {
	m.sendMu.Lock()
	defer m.sendMu.Unlock()

	return m.sendIntvl
}

func (m *Manager) getSendTables() []string {
	m.sendMu.Lock()
	defer m.sendMu.Unlock()

	return m.sendTables
}

func (m *Manager) send(ctx context.Context, tbls []string) error {
	m.store.RollUp()

	toSend := make(map[string][]DataPointGroup)
	tblMarks := make(map[string]WaterMarks)
	for _, name := range tbls {
		tbl := name

		tblMarks[tbl] = m.store.ForEachUnmarked(tbl, func(edgeIngr, _, _ string, pnts DataPoints) {
			toSend[tbl] = append(toSend[tbl], DataPointGroup{
				EdgeIngress: edgeIngr,
				DataPoints:  pnts,
			})
		})
	}

	if len(toSend) == 0 {
		return nil
	}

	if err := m.client.Send(ctx, toSend); err != nil {
		return err
	}

	for tbl, marks := range tblMarks {
		m.store.CommitMarks(tbl, marks)
	}
	m.store.Cleanup()

	return nil
}

func (m *Manager) startScraper(ctx context.Context) {
	mtrcs, err := m.scraper.Scrape(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Unable to scrape metrics")
		return
	}

	ref := Aggregate(mtrcs)

	tick := time.NewTicker(scrapeInterval)
	defer tick.Stop()

	scrapeSec := int64(scrapeInterval.Seconds())
	for {
		select {
		case <-ctx.Done():
			return

		case <-tick.C:
			mtrcs, err = m.scraper.Scrape(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Unable to scrape metrics")
				return
			}

			mtrcSet := Aggregate(mtrcs)

			ts := time.Now().UTC().Truncate(time.Minute).Unix()

			pnts := make(map[SetKey]DataPoint, len(mtrcSet))
			for key, mtrc := range mtrcSet {
				mtrc = mtrc.RelativeTo(ref[key])

				pnt := mtrc.ToDataPoint(scrapeSec)
				pnt.Timestamp = ts
				pnt.Seconds = scrapeSec

				pnts[key] = pnt
			}

			m.store.Insert(pnts)

			ref = mtrcSet
		}
	}
}
