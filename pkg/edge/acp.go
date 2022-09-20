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

import (
	"time"

	"github.com/traefik/hub-agent-traefik/pkg/acp/basicauth"
	"github.com/traefik/hub-agent-traefik/pkg/acp/jwt"
	"github.com/traefik/hub-agent-traefik/pkg/acp/oidc"
)

// ACP is an Access Control Policy definition.
type ACP struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspaceId"`
	ClusterID   string `json:"clusterId"`

	Version string `json:"version"`

	Name       string            `json:"name"`
	JWT        *jwt.Config       `json:"jwt"`
	BasicAuth  *basicauth.Config `json:"basicAuth"`
	OIDC       *oidc.Config      `json:"oidc"`
	OIDCGoogle *OIDCGoogle       `json:"oidcGoogle"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// OIDCGoogle is the Google OIDC configuration.
type OIDCGoogle struct {
	oidc.Config

	Emails []string `json:"emails,omitempty"`
}
