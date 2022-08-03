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

// Reference describes a Reference.
type Reference struct {
	Topology Cluster `json:"topology"`
	Version  int64   `json:"version"`
}

// Cluster describes a Cluster.
type Cluster struct {
	Services map[string]*Service `json:"services"`
}

// Service describes a Service.
type Service struct {
	Name          string     `json:"name"`
	Container     *Container `json:"container,omitempty"`
	ExternalPorts []int      `json:"externalPorts,omitempty"`
}

// Container describes a container.
type Container struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
}
