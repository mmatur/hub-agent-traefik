package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/logger"
)

// APIError represents an error returned by the API.
type APIError struct {
	StatusCode int
	Message    string `json:"error"`
}

func (a APIError) Error() string {
	return fmt.Sprintf("failed with code %d: %s", a.StatusCode, a.Message)
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

type linkClusterReq struct {
	Platform string `json:"platform"`
}

type linkClusterResp struct {
	ClusterID string `json:"clusterId"`
}

// Link links the agent to the Hub platform.
func (c *Client) Link(ctx context.Context) (clusterID string, err error) {
	body, err := json.Marshal(linkClusterReq{Platform: "other"})
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

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		apiErr := APIError{StatusCode: resp.StatusCode}
		if err = json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			return "", fmt.Errorf("failed with code %d: decode response: %w", resp.StatusCode, err)
		}

		return "", apiErr
	}

	var linkResp linkClusterResp
	if err = json.NewDecoder(resp.Body).Decode(&linkResp); err != nil {
		return "", fmt.Errorf("decode link agent resp: %w", err)
	}

	return linkResp.ClusterID, nil
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

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		apiErr := APIError{StatusCode: resp.StatusCode}
		if err = json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			return Config{}, fmt.Errorf("failed with code %d: decode response: %w", resp.StatusCode, err)
		}

		return Config{}, apiErr
	}

	var cfg Config
	if err = json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
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

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed with code %d", resp.StatusCode)
	}
	return nil
}
