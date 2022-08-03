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

package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/traefik/hub-agent-traefik/pkg/version"
)

// APIError represents an error returned by the API.
type APIError struct {
	StatusCode int
	Message    string `json:"error"`
}

func (a APIError) Error() string {
	return fmt.Sprintf("failed with code %d: %s", a.StatusCode, a.Message)
}

type descriptor struct {
	ID      int    `json:"id"`
	RuleID  string `json:"ruleId"`
	Ingress string `json:"ingress"`
	Service string `json:"service,omitempty"`
}

// Client for the alerting service.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client

	token string
}

// NewClient creates an alerting service client.
func NewClient(client *http.Client, baseURL, token string) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid alerting client url: %w", err)
	}

	return &Client{
		baseURL:    base,
		httpClient: client,
		token:      token,
	}, nil
}

// GetRules gets the agent configuration.
func (c *Client) GetRules(ctx context.Context) ([]Rule, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "rules"))
	if err != nil {
		return nil, fmt.Errorf("creating alerting rules url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	var rules []Rule
	err = c.do(req, &rules)
	if err != nil {
		return nil, err
	}

	return rules, nil
}

// PreflightAlerts sends alert descriptors to the server and returns which alerts to send.
func (c *Client) PreflightAlerts(ctx context.Context, data []Alert) ([]Alert, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "preflight"))
	if err != nil {
		return nil, fmt.Errorf("creating alerts url: %w", err)
	}

	descriptors := make([]descriptor, len(data))
	for i, alert := range data {
		descriptors[i] = descriptor{
			ID:      i,
			RuleID:  alert.RuleID,
			Ingress: alert.Ingress,
			Service: alert.Service,
		}
	}

	body, err := json.Marshal(descriptors)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	var pos []int
	err = c.do(req, &pos)
	if err != nil {
		return nil, err
	}

	if len(pos) == 0 {
		return nil, nil
	}

	var allowed []Alert
	for _, i := range pos {
		if i < 0 || i >= len(data) {
			return nil, fmt.Errorf("invalid alert position: %d", i)
		}
		allowed = append(allowed, data[i])
	}

	return allowed, nil
}

// SendAlerts sends alerts to the server.
func (c *Client) SendAlerts(ctx context.Context, data []Alert) error {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "notify"))
	if err != nil {
		return fmt.Errorf("creating alerts url: %w", err)
	}

	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	return c.do(req, nil)
}

func (c *Client) do(req *http.Request, result interface{}) error {
	req.Header.Set("Authorization", "Bearer "+c.token)
	version.SetUserAgent(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		all, _ := io.ReadAll(resp.Body)

		apiErr := APIError{StatusCode: resp.StatusCode}
		if err = json.Unmarshal(all, &apiErr); err != nil {
			apiErr.Message = string(all)
		}

		return apiErr
	}

	if result != nil {
		if err = json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decode config: %w", err)
		}
	}

	return nil
}
