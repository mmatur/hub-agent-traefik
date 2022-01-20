package certificate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// APIError represents an error returned by the API.
type APIError struct {
	StatusCode int
	Message    string `json:"error"`
}

func (a APIError) Error() string {
	return fmt.Sprintf("failed with code %d: %s", a.StatusCode, a.Message)
}

// Client allows interacting with the certificates service.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client

	token string
}

// NewClient creates a new certificates for the certificates service.
func NewClient(baseURL, token string) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate client url: %w", err)
	}

	return &Client{
		baseURL: base,
		token:   token,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

// Certificate represents the certificate returned by the platform.
type Certificate struct {
	Domains     []string  `json:"domains"`
	NotAfter    time.Time `json:"notAfter"`
	NotBefore   time.Time `json:"notBefore"`
	Certificate []byte    `json:"certificate"`
	PrivateKey  []byte    `json:"privateKey"`
}

// ErrCertIssuancePending is returned when certificate issuance is pending.
var ErrCertIssuancePending = errors.New("certificate issuance is pending")

// Obtain obtains a certificate for the given domains.
func (c *Client) Obtain(domains []string) (Certificate, error) {
	baseURL, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "/certificates"))
	if err != nil {
		return Certificate{}, fmt.Errorf("parse endpoint: %w", err)
	}

	query := baseURL.Query()
	query.Set("domains", strings.Join(domains, ","))
	baseURL.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), http.NoBody)
	if err != nil {
		return Certificate{}, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Certificate{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	// The certificate is not yet available.
	if resp.StatusCode == http.StatusAccepted {
		return Certificate{}, ErrCertIssuancePending
	}

	if resp.StatusCode != http.StatusOK {
		apiErr := APIError{StatusCode: resp.StatusCode}
		if err = json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			return Certificate{}, fmt.Errorf("failed with code %d: decode response: %w", resp.StatusCode, err)
		}

		return Certificate{}, apiErr
	}

	var cert Certificate
	if err = json.NewDecoder(resp.Body).Decode(&cert); err != nil {
		return Certificate{}, fmt.Errorf("decode obtain resp: %w", err)
	}

	return cert, nil
}
