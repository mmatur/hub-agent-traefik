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

package edge

import "time"

// ACP is an Access Control Policy definition.
type ACP struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspaceId"`
	ClusterID   string `json:"clusterId"`

	Version string `json:"version"`

	Name      string              `json:"name"`
	JWT       *ACPJWTConfig       `json:"jwt"`
	BasicAuth *ACPBasicAuthConfig `json:"basicAuth"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ACPJWTConfig configures a JWT ACP handler.
type ACPJWTConfig struct {
	SigningSecret              string            `json:"signingSecret"`
	SigningSecretBase64Encoded bool              `json:"signingSecretBase64Encoded"`
	PublicKey                  string            `json:"publicKey"`
	JWKsFile                   FileOrContent     `json:"jwksFile"`
	JWKsURL                    string            `json:"jwksUrl"`
	StripAuthorizationHeader   bool              `json:"stripAuthorizationHeader"`
	ForwardHeaders             map[string]string `json:"forwardHeaders"`
	TokenQueryKey              string            `json:"tokenQueryKey"`
	Claims                     string            `json:"claims"`
}

// ACPBasicAuthConfig configures a basic auth ACP handler.
type ACPBasicAuthConfig struct {
	Users                    []string `json:"users"`
	Realm                    string   `json:"realm"`
	StripAuthorizationHeader bool     `json:"stripAuthorizationHeader"`
	ForwardUsernameHeader    string   `json:"forwardUsernameHeader"`
}
