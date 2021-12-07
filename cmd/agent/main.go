package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/traefik/neo-agent/pkg/logger"
	"github.com/traefik/neo-agent/pkg/version"
	"github.com/urfave/cli/v2"
)

const flagLogLevel = "log-level"

func main() {
	err := run()
	if err != nil {
		log.Fatal().Err(err).Msg("Error while executing command")
	}
}

func run() error {
	app := &cli.App{
		Name:  "neo-agent",
		Usage: "Start the neo-agent",

		Action: func(cliCtx *cli.Context) error {
			logger.Setup(cliCtx.String(flagLogLevel))

			log.Info().
				Str("date", version.BuildDate()).
				Str("version", version.Version()).
				Str("commit", version.Commit()).
				Str("module", version.ModuleName()).Send()

			return nil
		},
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return app.RunContext(ctx, os.Args)
}
