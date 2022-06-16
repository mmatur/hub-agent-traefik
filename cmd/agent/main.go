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

package main

import (
	"context"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/version"
	"github.com/urfave/cli/v2"
)

const (
	flagAuthServerListenAddr               = "auth-server.listen-addr"
	flagAuthServerAdvertiseURL             = "auth-server.advertise-url"
	flagHubToken                           = "hub.token"
	flagHubURL                             = "hub.url"
	flagHubUIURL                           = "hub.ui.url"
	flagLogLevel                           = "log.level"
	flagLogFormat                          = "log.format"
	flagTraefikHost                        = "traefik.host"
	flagTraefikAPIPort                     = "traefik.api-port"
	flagTraefikTunnelPort                  = "traefik.tunnel-port"
	flagTraefikTLSCA                       = "traefik.tls.ca"
	flagTraefikTLSCert                     = "traefik.tls.cert"
	flagTraefikTLSKey                      = "traefik.tls.key"
	flagTraefikTLSInsecure                 = "traefik.tls.insecure"
	flagTraefikDockerSwarmMode             = "traefik.docker.swarm-mode"
	flagTraefikDockerEndpoint              = "traefik.docker.endpoint"
	flagTraefikDockerHTTPClientTimeout     = "traefik.docker.http-client-timeout"
	flagTraefikDockerTLSCA                 = "traefik.docker.tls.ca"
	flagTraefikDockerTLSCAOptional         = "traefik.docker.tls.ca-optional"
	flagTraefikDockerTLSCert               = "traefik.docker.tls.cert"
	flagTraefikDockerTLSKey                = "traefik.docker.tls.key"
	flagTraefikDockerTLSInsecureSkipVerify = "traefik.docker.tls.insecure-skip-verify"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("Error while executing command")
	}
}

func run() error {
	app := &cli.App{
		Name:  "Traefik Hub agent for Traefik",
		Usage: "Manages a Traefik Hub agent installation",
		Commands: []*cli.Command{
			newRunCmd().build(),
			newVersionCmd().build(),
		},
		Version: version.String(),
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return app.RunContext(ctx, os.Args)
}
