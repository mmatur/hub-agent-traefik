package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	flagTraefikAddr          = "traefik-addr"
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
			&cli.StringFlag{
				Name:     flagTraefikAddr,
				Usage:    "Address on which the Agent can reach Traefik",
				EnvVars:  []string{strcase.ToSNAKE(flagTraefikAddr)},
				Required: true,
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

	platformURL, token := cliCtx.String(flagPlatformURL), cliCtx.String("token")
	platformClient, err := platform.NewClient(platformURL, token)
	if err != nil {
		return fmt.Errorf("new platform client: %w", err)
	}

	if err = platformClient.Link(cliCtx.Context); err != nil {
		return fmt.Errorf("link agent: %w", err)
	}

	agentCfg, err := platformClient.GetConfig(cliCtx.Context)
	if err != nil {
		return fmt.Errorf("fetch agent config: %w", err)
	}

	heartbeater := heartbeat.NewHeartbeater(platformClient)

	listenAddr, acpDir := cliCtx.String(flagAuthServerListenAddr), cliCtx.String(flagAuthServerACPDir)

	traefikAddr := cliCtx.String(flagTraefikAddr)
	cfgWatcher := platform.NewConfigWatcher(15*time.Minute, platformClient)
	mtrcsMgr, _, err := newMetrics(token, platformURL, agentCfg.Metrics, cfgWatcher)
	if err != nil {
		return err
	}

	group, ctx := errgroup.WithContext(cliCtx.Context)
	group.Go(func() error {
		heartbeater.Run(ctx)
		return nil
	})

	group.Go(func() error {
		return auth.RunACPServer(ctx, listenAddr, acpDir)
	})

	group.Go(func() error {
		return mtrcsMgr.Run(ctx, traefikAddr)
	})

	return group.Wait()
}
