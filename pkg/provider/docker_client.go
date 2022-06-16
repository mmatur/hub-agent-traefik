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

package provider

import (
	"fmt"
	"net/http"
	"time"

	"github.com/docker/cli/cli/connhelper"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/sockets"
)

// Docker API versions.
const (
	DockerAPIVersion = "1.24"
	SwarmAPIVersion  = "1.24"
)

// DockerClientOpts Docker client.
type DockerClientOpts struct {
	HTTPClientTimeout time.Duration
	Endpoint          string
	SwarmMode         bool
	TLSClientConfig   *ClientTLS
}

// CreateDockerClient creates Docker client.
func CreateDockerClient(dcOps DockerClientOpts) (*client.Client, error) {
	opts, err := getClientOpts(dcOps)
	if err != nil {
		return nil, err
	}

	httpHeaders := map[string]string{
		"User-Agent": "Traefik Hub Agent",
	}
	opts = append(opts, client.WithHTTPHeaders(httpHeaders))

	apiVersion := DockerAPIVersion
	if dcOps.SwarmMode {
		apiVersion = SwarmAPIVersion
	}
	opts = append(opts, client.WithVersion(apiVersion))

	return client.NewClientWithOpts(opts...)
}

func getClientOpts(dcOps DockerClientOpts) ([]client.Opt, error) {
	helper, err := connhelper.GetConnectionHelper(dcOps.Endpoint)
	if err != nil {
		return nil, err
	}

	// SSH
	if helper != nil {
		// https://github.com/docker/cli/blob/ebca1413117a3fcb81c89d6be226dcec74e5289f/cli/context/docker/load.go#L112-L123
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: helper.Dialer,
			},
		}

		return []client.Opt{
			client.WithHTTPClient(httpClient),
			client.WithTimeout(dcOps.HTTPClientTimeout),
			client.WithHost(helper.Host), // To avoid 400 Bad Request: malformed Host header daemon error
			client.WithDialContext(helper.Dialer),
		}, nil
	}

	opts := []client.Opt{
		client.WithHost(dcOps.Endpoint),
		client.WithTimeout(dcOps.HTTPClientTimeout),
	}

	if dcOps.TLSClientConfig != nil {
		conf, err := dcOps.TLSClientConfig.CreateTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to create client TLS configuration: %w", err)
		}

		hostURL, err := client.ParseHostURL(dcOps.Endpoint)
		if err != nil {
			return nil, err
		}

		tr := &http.Transport{
			TLSClientConfig: conf,
		}

		if err := sockets.ConfigureTransport(tr, hostURL.Scheme, hostURL.Host); err != nil {
			return nil, err
		}

		opts = append(opts, client.WithHTTPClient(&http.Client{Transport: tr, Timeout: dcOps.HTTPClientTimeout}))
	}

	return opts, nil
}
