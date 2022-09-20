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

package oidc

import "errors"

// Config holds the OIDC authentication configuration.
type Config struct {
	Issuer       string `json:"issuer,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`

	RedirectURL string            `json:"redirectUrl,omitempty"`
	LogoutURL   string            `json:"logoutUrl,omitempty"`
	AuthParams  map[string]string `json:"authParams,omitempty"`

	Key         string      `json:"-"`
	StateCookie StateCookie `json:"stateCookie,omitempty"`
	Session     Session     `json:"session,omitempty"`

	Scopes         []string          `json:"scopes,omitempty"`
	ForwardHeaders map[string]string `json:"forwardHeaders,omitempty"`
	Claims         string            `json:"claims,omitempty"`
}

// ApplyDefaultValues applies default values on the given dynamic configuration.
func (cfg *Config) ApplyDefaultValues() {
	if cfg == nil {
		return
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid"}
	}

	if cfg.StateCookie.Path == "" {
		cfg.StateCookie.Path = "/"
	}

	if cfg.StateCookie.SameSite == "" {
		cfg.StateCookie.SameSite = "lax"
	}

	if cfg.Session.Path == "" {
		cfg.Session.Path = "/"
	}

	if cfg.Session.SameSite == "" {
		cfg.Session.SameSite = "lax"
	}

	if cfg.Session.Refresh == nil {
		cfg.Session.Refresh = func(b bool) *bool { return &b }(true)
	}

	if cfg.RedirectURL == "" {
		cfg.RedirectURL = "/callback"
	}
}

// Validate validates configuration.
func (cfg *Config) Validate() error {
	if cfg == nil {
		return nil
	}

	cfg.ApplyDefaultValues()

	if cfg.Issuer == "" {
		return errors.New("missing issuer")
	}

	if cfg.ClientID == "" {
		return errors.New("missing client ID")
	}

	if cfg.ClientSecret == "" {
		return errors.New("missing client secret")
	}

	if cfg.Key == "" {
		return errors.New("missing key")
	}

	switch len(cfg.Key) {
	case 16, 24, 32:
		break
	default:
		return errors.New("key must be 16, 24 or 32 characters long")
	}

	return nil
}

// TLS holds tls information.
type TLS struct {
	CABundle           []byte `json:"caBundle,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
}

// StateCookie holds state cookie configuration.
type StateCookie struct {
	SameSite string `json:"sameSite,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Session holds session configuration.
type Session struct {
	SameSite string `json:"sameSite,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Refresh  *bool  `json:"refresh,omitempty"`
}
