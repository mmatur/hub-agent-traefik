package acp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/traefik/neo-agent/pkg/logger"
)

// Client allows interacting with a Traefik instance.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client

	token string
}

// NewClient returns a new Client.
func NewClient(baseURL, token string) (*Client, error) {
	u, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	rc := retryablehttp.NewClient()
	rc.RetryMax = 4
	rc.Logger = logger.NewWrappedLogger(log.Logger.With().Str("component", "acp-client").Logger())

	retryClient := rc.StandardClient()

	return &Client{
		baseURL:    u,
		httpClient: retryClient,
		token:      token,
	}, nil
}

type acpResp struct {
	Config

	Name string `json:"name"`
}

// GetACPs gets ACPs from Hub.
func (c *Client) GetACPs(ctx context.Context) (map[string]Config, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "acps"))
	if err != nil {
		return nil, fmt.Errorf("get ACPS url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request for %q: %w", c.baseURL.String(), err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code %d; got %d", http.StatusOK, resp.StatusCode)
	}

	var acps []acpResp
	if err := json.NewDecoder(resp.Body).Decode(&acps); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	configs := map[string]Config{}
	for _, acp := range acps {
		configs[acp.Name] = acp.Config
	}

	return configs, nil
}
