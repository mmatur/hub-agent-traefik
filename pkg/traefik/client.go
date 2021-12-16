package traefik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/neo-agent/pkg/logger"
)

// Client allows interacting with a Traefik instance.
type Client struct {
	baseURL *url.URL

	httpClient *http.Client
}

// NewClient returns a new Client.
func NewClient(baseURL string) (*Client, error) {
	u, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	rc := retryablehttp.NewClient()
	rc.RetryMax = 4
	rc.Logger = logger.NewWrappedLogger(log.Logger.With().Str("component", "traefik-client").Logger())

	retryClient := rc.StandardClient()

	return &Client{
		baseURL:    u,
		httpClient: retryClient,
	}, nil
}

// PushDynamic pushes a dynamic configuration.
func (c *Client) PushDynamic(ctx context.Context, cfg *dynamic.Configuration) error {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "config"))
	if err != nil {
		return err
	}

	b, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("serialize configuration: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build request for %q: %w", endpoint.String(), err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %q: %w", endpoint.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d; got %d", http.StatusOK, resp.StatusCode)
	}

	return nil
}

// GetAgentReachableIP returns an IP address the Hub plugin can reach the Agent from.
func (c *Client) GetAgentReachableIP(ctx context.Context) (string, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "discover-ip"))
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("build request for %q: %w", endpoint.String(), err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request %q: %w", endpoint.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected status code %d; got %d", http.StatusOK, resp.StatusCode)
	}

	var ip string
	if err = json.NewDecoder(resp.Body).Decode(&ip); err != nil {
		return "", fmt.Errorf("deserialize ip: %w", err)
	}

	return ip, nil
}
