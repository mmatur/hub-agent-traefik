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

package metrics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/hamba/avro"
	"github.com/traefik/hub-agent-traefik/pkg/metrics/protocol"
	"github.com/traefik/hub-agent-traefik/pkg/version"
)

// Client for the token service.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client

	metricsSchema avro.Schema

	token string
}

// NewClient creates a token service client.
func NewClient(client *http.Client, baseURL, token string) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid metrics client url: %w", err)
	}

	metricsSchema, err := avro.Parse(protocol.MetricsV2Schema)
	if err != nil {
		return nil, fmt.Errorf("invalid metrics schema: %w", err)
	}

	return &Client{
		baseURL:       base,
		httpClient:    client,
		metricsSchema: metricsSchema,
		token:         token,
	}, nil
}

// GetPreviousData gets the agent configuration.
func (c *Client) GetPreviousData(ctx context.Context, startup bool) (map[string][]DataPointGroup, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "data"))
	if err != nil {
		return nil, fmt.Errorf("creating metrics previous data url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	data := map[string][]DataPointGroup{}
	err = c.do(req, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Send sends metrics to the metrics service.
func (c *Client) Send(ctx context.Context, data map[string][]DataPointGroup) error {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "metrics"))
	if err != nil {
		return fmt.Errorf("creating metrics url: %w", err)
	}

	raw, err := avro.Marshal(c.metricsSchema, data)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	return c.do(req, nil)
}

func (c *Client) do(req *http.Request, result interface{}) error {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "avro/binary;v2")
	req.Header.Set("Content-Type", "avro/binary;v2")
	version.SetUserAgent(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		all, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("%d: %s", resp.StatusCode, string(all))
	}

	if result != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response body: %w", err)
		}

		if err = avro.Unmarshal(c.metricsSchema, body, &result); err != nil {
			return fmt.Errorf("unmarshalling response: %w: %s", err, string(body))
		}
	}

	return nil
}
