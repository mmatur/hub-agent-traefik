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

package platform

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/logger"
	"github.com/traefik/hub-agent-traefik/pkg/topology"
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

// Config holds the configuration of the agent.
type Config struct {
	Metrics       MetricsConfig       `json:"metrics"`
	Topology      TopologyConfig      `json:"topology"`
	AccessControl AccessControlConfig `json:"accessControl"`
}

// TopologyConfig holds the topology part of the agent config.
type TopologyConfig struct {
	GitProxyHost string `json:"gitProxyHost,omitempty"`
	GitOrgName   string `json:"gitOrgName,omitempty"`
	GitRepoName  string `json:"gitRepoName,omitempty"`
}

// MetricsConfig holds the metrics part of the agent config.
type MetricsConfig struct {
	Interval time.Duration `json:"interval"`
	Tables   []string      `json:"tables"`
}

// AccessControlConfig holds the configuration of the access control section of the offer config.
type AccessControlConfig struct {
	MaxSecuredRoutes int `json:"maxSecuredRoutes"`
}

type linkClusterReq struct {
	Platform string `json:"platform"`
	Version  string `json:"version"`
}

type linkClusterResp struct {
	ClusterID string `json:"clusterId"`
}

type patchResp struct {
	Version int64 `json:"version"`
}

// Client allows interacting with the cluster service.
type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

// NewClient creates a new client for the cluster service.
func NewClient(baseURL, token string) (*Client, error) {
	u, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, err
	}

	rc := retryablehttp.NewClient()
	rc.RetryMax = 4
	rc.Logger = logger.NewRetryableHTTPWrapper(log.Logger.With().Str("component", "platform-client").Logger())

	return &Client{
		baseURL:    u,
		token:      token,
		httpClient: rc.StandardClient(),
	}, nil
}

// Link links the agent to the Hub platform.
func (c *Client) Link(ctx context.Context) (clusterID string, err error) {
	body, err := json.Marshal(linkClusterReq{Platform: "other", Version: version.Version()})
	if err != nil {
		return "", fmt.Errorf("marshal link agent request: %w", err)
	}

	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "link"))
	if err != nil {
		return "", fmt.Errorf("parse endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}

	var linkResp linkClusterResp
	err = c.do(req, &linkResp)
	if err != nil {
		return "", err
	}

	return linkResp.ClusterID, nil
}

// GetConfig returns the agent configuration.
func (c *Client) GetConfig(ctx context.Context) (Config, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "config"))
	if err != nil {
		return Config{}, fmt.Errorf("parse endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return Config{}, fmt.Errorf("build request: %w", err)
	}

	var cfg Config
	err = c.do(req, &cfg)
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Ping sends a ping to the platform to inform that the agent is alive.
func (c *Client) Ping(ctx context.Context) error {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "ping"))
	if err != nil {
		return fmt.Errorf("parse endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
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

	body, err := readBody(resp)
	if err != nil {
		return APIError{StatusCode: resp.StatusCode, Message: err.Error()}
	}

	if resp.StatusCode/100 != 2 {
		apiErr := APIError{StatusCode: resp.StatusCode}
		if err = json.Unmarshal(body, &apiErr); err != nil {
			apiErr.Message = string(body)
		}

		return apiErr
	}

	if result != nil {
		if err = json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// FetchTopology fetches the topology.
func (c *Client) FetchTopology(ctx context.Context) (topology.Reference, error) {
	baseURL, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "topology"))
	if err != nil {
		return topology.Reference{}, fmt.Errorf("parse endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), http.NoBody)
	if err != nil {
		return topology.Reference{}, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept-Encoding", "gzip")

	var r topology.Reference
	err = c.do(req, &r)
	if err != nil {
		return topology.Reference{}, err
	}

	return r, nil
}

// SetVersionStatus sends the current version status to the platform.
func (c *Client) SetVersionStatus(ctx context.Context, status version.Status) error {
	baseURL, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "version-status"))
	if err != nil {
		return fmt.Errorf("parse endpoint: %w", err)
	}

	body, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("marshal status: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	version.SetUserAgent(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		all, _ := io.ReadAll(resp.Body)

		apiErr := APIError{StatusCode: resp.StatusCode}
		if err = json.Unmarshal(all, &apiErr); err != nil {
			apiErr.Message = string(all)
		}

		return apiErr
	}

	return nil
}

// PatchTopology submits a JSON Merge Patch to the platform containing the difference in the topology since its last synchronization.
// The last known topology version must be provided.
// This version can be obtained by calling the FetchTopology method.
func (c *Client) PatchTopology(ctx context.Context, patch []byte, lastKnownVersion int64) (int64, error) {
	baseURL, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "topology"))
	if err != nil {
		return 0, fmt.Errorf("parse endpoint: %w", err)
	}

	req, err := newGzippedRequestWithContext(ctx, http.MethodPatch, baseURL.String(), patch)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/merge-patch+json")
	req.Header.Set("Last-Known-Version", strconv.FormatInt(lastKnownVersion, 10))

	// This operation cannot be retried without calling FetchTopology in between.
	var body patchResp
	err = c.do(req, &body)
	if err != nil {
		return 0, err
	}

	return body.Version, nil
}

func newGzippedRequestWithContext(ctx context.Context, verb, u string, body []byte) (*http.Request, error) {
	var compressedBody bytes.Buffer

	writer := gzip.NewWriter(&compressedBody)
	_, err := writer.Write(body)
	if err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err = writer.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, verb, u, &compressedBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Encoding", "gzip")

	return req, nil
}

func readBody(resp *http.Response) ([]byte, error) {
	contentEncoding := resp.Header.Get("Content-Encoding")

	switch contentEncoding {
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("create gzip reader: %w", err)
		}
		defer func() { _ = reader.Close() }()

		return io.ReadAll(reader)
	case "":
		return io.ReadAll(resp.Body)
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", contentEncoding)
	}
}
