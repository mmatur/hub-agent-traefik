package main

import (
	"context"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/neo-agent/pkg/version"
	"github.com/urfave/cli/v2"
)

const (
	flagLogLevel                = "log-level"
	flagLogFormat               = "log-format"
	flagTraefikAddr             = "traefik-addr"
	flagToken                   = "token"
	flagPlatformURL             = "platform-url"
	flagAuthServerListenAddr    = "auth-server-listen-addr"
	flagAuthServerReachableAddr = "auth-server-reachable-addr"
	flagAuthServerACPDir        = "auth-server-acp-dir"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("Error while executing command")
	}
}

func run() error {
	app := &cli.App{
		Name:  "Neo agent CLI",
		Usage: "Manages a Traefik Neo agent installation",
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
