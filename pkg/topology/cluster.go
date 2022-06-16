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

package topology

import "github.com/traefik/genconf/dynamic/types"

// Cluster describes a Cluster.
type Cluster struct {
	ID                    string
	Overview              Overview
	IngressRoutes         map[string]*IngressRoute `dir:"Ingresses"`
	Services              map[string]*Service
	IngressControllers    map[string]*IngressController
	AccessControlPolicies map[string]*AccessControlPolicy
}

// Overview represents an overview of the cluster resources.
type Overview struct {
	IngressCount           int      `json:"ingressCount"`
	ServiceCount           int      `json:"serviceCount"`
	IngressControllerTypes []string `json:"ingressControllerTypes"`
}

// ResourceMeta represents the metadata that identifies a Kubernetes resource.
type ResourceMeta struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// IngressController is an abstraction of Deployments/ReplicaSets/DaemonSets/StatefulSets that
// are a cluster's IngressController. Used only for compatibility purpose in the multiplatform case.
type IngressController struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Type string `json:"type"`
}

// Service describes a Service.
type Service struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	ClusterID string     `json:"clusterId"`
	Container *Container `json:"container,omitempty"`
	Ports     []int      `json:"externalPorts,omitempty"`
}

// Container describes a container.
type Container struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
}

// IngressMeta represents the common Ingress metadata properties.
type IngressMeta struct {
	ClusterID      string            `json:"clusterId"`
	ControllerType string            `json:"controllerType,omitempty"`
	Annotations    map[string]string `json:"annotations,omitempty"`
}

// IngressRoute describes a Traefik IngressRoute.
type IngressRoute struct {
	ResourceMeta
	IngressMeta

	TLS      *IngressRouteTLS `json:"tls,omitempty"`
	Routes   []Route          `json:"routes,omitempty"`
	Services []string         `json:"services,omitempty"`
}

// IngressRouteTLS represents a simplified Traefik IngressRoute TLS configuration.
type IngressRouteTLS struct {
	Domains []types.Domain `json:"domains,omitempty"`
	Options *TLSOptionRef  `json:"options,omitempty"`
}

// TLSOptionRef references TLSOptions.
type TLSOptionRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Route represents a Traefik IngressRoute route.
type Route struct {
	Match    string         `json:"match"`
	Services []RouteService `json:"services,omitempty"`
}

// RouteService represents a Kubernetes service targeted by a Traefik IngressRoute route.
type RouteService struct {
	Name string `json:"name"`
}

// AccessControlPolicy describes an Access Control Policy configured within a cluster.
type AccessControlPolicy struct {
	Name      string                        `json:"name"`
	ClusterID string                        `json:"clusterId"`
	Method    string                        `json:"method"`
	JWT       *AccessControlPolicyJWT       `json:"jwt,omitempty"`
	BasicAuth *AccessControlPolicyBasicAuth `json:"basicAuth,omitempty"`
}

// AccessControlPolicyJWT describes the settings for JWT authentication within an access control policy.
type AccessControlPolicyJWT struct {
	SigningSecret              string            `json:"signingSecret,omitempty"`
	SigningSecretBase64Encoded bool              `json:"signingSecretBase64Encoded"`
	PublicKey                  string            `json:"publicKey,omitempty"`
	JWKsFile                   string            `json:"jwksFile,omitempty"`
	JWKsURL                    string            `json:"jwksUrl,omitempty"`
	StripAuthorizationHeader   bool              `json:"stripAuthorizationHeader,omitempty"`
	ForwardHeaders             map[string]string `json:"forwardHeaders,omitempty"`
	TokenQueryKey              string            `json:"tokenQueryKey,omitempty"`
	Claims                     string            `json:"claims,omitempty"`
}

// AccessControlPolicyBasicAuth holds the HTTP basic authentication configuration.
type AccessControlPolicyBasicAuth struct {
	Users                    string `json:"users,omitempty"`
	Realm                    string `json:"realm,omitempty"`
	StripAuthorizationHeader bool   `json:"stripAuthorizationHeader,omitempty"`
	ForwardUsernameHeader    string `json:"forwardUsernameHeader,omitempty"`
}
