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
	flagAuthServerListenAddr    = "auth-server.listen-addr"
	flagAuthServerAdvertiseAddr = "auth-server.advertise-addr"
	flagAuthServerACPDir        = "auth-server.acp-dir"
	flagHubToken                = "hub.token"
	flagHubURL                  = "hub.url"
	flagLogLevel                = "log.level"
	flagLogFormat               = "log.format"
	flagTraefikAddr             = "traefik.addr"
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
