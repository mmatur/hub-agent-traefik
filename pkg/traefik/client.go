package traefik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"

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

// RunTimeRepresentation holds the dynamic configuration return by Traefik API.
type RunTimeRepresentation struct {
	Routers  map[string]*dynamic.Router  `json:"routers,omitempty"`
	Services map[string]*dynamic.Service `json:"services,omitempty"`
}

// GetDynamic gets the dynamic configuration.
func (c *Client) GetDynamic(ctx context.Context) (*dynamic.Configuration, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "api/rawdata"))
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request for %q: %w", endpoint.String(), err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %q: %w", endpoint.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	var rawData RunTimeRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&rawData); err != nil {
		return nil, fmt.Errorf("decode rawdata: %w", err)
	}

	return &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers:  rawData.Routers,
			Services: rawData.Services,
		},
	}, nil
}

type configRequest struct {
	UnixNano      int64                  `json:"unixNano"`
	Configuration *dynamic.Configuration `json:"configuration"`
}

// PushDynamic pushes a dynamic configuration.
func (c *Client) PushDynamic(ctx context.Context, unixNano int64, cfg *dynamic.Configuration) error {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "config"))
	if err != nil {
		return err
	}

	payload := configRequest{
		UnixNano:      unixNano,
		Configuration: cfg,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("serialize configuration: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build request for %q: %w", endpoint.String(), err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d; got %d", http.StatusOK, resp.StatusCode)
	}

	return nil
}

// GetAgentReachableIP returns an IP address the Hub plugin can reach the Agent from.
func (c *Client) GetAgentReachableIP(ctx context.Context) (string, error) {
	// First, start an ephemeral HTTP server that Traefik will try to call to make sure the Agent is reachable.
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return "", err
	}

	port := listener.Addr().(*net.TCPAddr).Port
	nonce := generateNonce(16)

	mux := http.NewServeMux()

	var ok bool
	mux.HandleFunc("/", func(_ http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("nonce") == nonce {
			ok = true
		}
	})

	s := &http.Server{Handler: mux}
	defer func() { _ = s.Close() }()

	go func(s *http.Server) {
		if err = s.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("Unable to serve temporary discovery server")
			return
		}
	}(s)

	// Then, signal Traefik to try and call us.
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "discover-ip"))
	if err != nil {
		return "", err
	}

	q := make(url.Values)
	q.Set("port", strconv.Itoa(port))
	q.Set("nonce", nonce)
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("build request for %q: %w", endpoint.String(), err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var b []byte
		b, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("read body: %w", err)
		}
		return "", fmt.Errorf("expected status code %d; got %d: %s", http.StatusOK, resp.StatusCode, bytes.TrimSpace(b))
	}

	if !ok {
		return "", errors.New("ip discovery failed")
	}

	var ip string
	if err = json.NewDecoder(resp.Body).Decode(&ip); err != nil {
		return "", fmt.Errorf("deserialize ip: %w", err)
	}

	return ip, nil
}

// PluginState is the state of a Hub plugin.
type PluginState struct {
	PluginName         string `json:"pluginName"`
	LastConfigUnixNano int64  `json:"lastConfigUnixNano"`
}

// GetPluginState returns the current PluginState.
func (c *Client) GetPluginState(ctx context.Context) (PluginState, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "state"))
	if err != nil {
		return PluginState{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return PluginState{}, fmt.Errorf("build request for %q: %w", endpoint.String(), err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return PluginState{}, fmt.Errorf("request %q: %w", endpoint.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return PluginState{}, fmt.Errorf("expected status code %d; got %d", http.StatusOK, resp.StatusCode)
	}

	var ps PluginState
	if err = json.NewDecoder(resp.Body).Decode(&ps); err != nil {
		return PluginState{}, fmt.Errorf("deserialize plugin state: %w", err)
	}

	return ps, nil
}

func generateNonce(n int) string {
	charSet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = charSet[rand.Intn(len(charSet))]
	}

	return string(b)
}
