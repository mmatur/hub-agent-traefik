package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ettle/strcase"
	"github.com/rs/zerolog/log"
	"github.com/traefik/neo-agent/pkg/acp/auth"
	"github.com/traefik/neo-agent/pkg/heartbeat"
	"github.com/traefik/neo-agent/pkg/logger"
	"github.com/traefik/neo-agent/pkg/platform"
	"github.com/traefik/neo-agent/pkg/version"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

const (
	flagLogLevel             = "log-level"
	flagLogFormat            = "log-format"
	flagToken                = "token"
	flagPlatformURL          = "platform-url"
	flagAuthServerListenAddr = "auth-server-listen-addr"
	flagAuthServerACPDir     = "auth-server-acp-dir"
)

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("Error while executing command")
	}
}

func run() error {
	app := &cli.App{
		Name:  "neo-agent",
		Usage: "Start the neo-agent",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    flagLogLevel,
				Usage:   "Log level to use (debug, info, warn, error or fatal)",
				EnvVars: []string{strcase.ToSNAKE(flagLogLevel)},
				Value:   "info",
			},
			&cli.StringFlag{
				Name:    flagLogFormat,
				Usage:   "Log format to use (json or console)",
				EnvVars: []string{strcase.ToSNAKE(flagLogFormat)},
				Value:   "json",
			},
			&cli.StringFlag{
				Name:     flagToken,
				Usage:    "The token to use for Hub platform API calls",
				EnvVars:  []string{strcase.ToSNAKE(flagToken)},
				Required: true,
			},
			&cli.StringFlag{
				Name:    flagPlatformURL,
				Usage:   "The URL where to reach the Hub platform API",
				Value:   "https://platform.hub.traefik.io/agent",
				EnvVars: []string{strcase.ToSNAKE(flagPlatformURL)},
				Hidden:  true,
			},
			&cli.StringFlag{
				Name:    flagAuthServerListenAddr,
				Usage:   "Address on which the auth server listens for auth requests",
				EnvVars: []string{strcase.ToSNAKE(flagAuthServerListenAddr)},
				Value:   "0.0.0.0:80",
			},
			&cli.StringFlag{
				Name:    flagAuthServerACPDir,
				Usage:   "Directory path containing Access Control Policy configurations",
				EnvVars: []string{strcase.ToSNAKE(flagAuthServerACPDir)},
				Value:   "./acps",
			},
		},
		Action: runAgent,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return app.RunContext(ctx, os.Args)
}

func runAgent(cliCtx *cli.Context) error {
	logger.Setup(cliCtx.String(flagLogLevel), cliCtx.String(flagLogFormat))

	log.Info().
		Str("date", version.BuildDate()).
		Str("version", version.Version()).
		Str("commit", version.Commit()).
		Str("module", version.ModuleName()).Send()

	platformURL, token := cliCtx.String(flagPlatformURL), cliCtx.String(flagToken)
	platformClient := platform.NewClient(platformURL, token)

	if err := platformClient.Link(cliCtx.Context); err != nil {
		return fmt.Errorf("link agent: %w", err)
	}

	heartbeater := heartbeat.NewHeartbeater(platformClient)

	listenAddr, acpDir := cliCtx.String(flagAuthServerListenAddr), cliCtx.String(flagAuthServerACPDir)

	group, ctx := errgroup.WithContext(cliCtx.Context)

	group.Go(func() error {
		heartbeater.Run(ctx)
		return nil
	})

	group.Go(func() error {
		return auth.RunACPServer(ctx, listenAddr, acpDir)
	})

	return group.Wait()
}
