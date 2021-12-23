package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ettle/strcase"
	"github.com/rs/zerolog/log"
	"github.com/traefik/neo-agent/pkg/acp"
	"github.com/traefik/neo-agent/pkg/certificate"
	"github.com/traefik/neo-agent/pkg/heartbeat"
	"github.com/traefik/neo-agent/pkg/logger"
	"github.com/traefik/neo-agent/pkg/platform"
	"github.com/traefik/neo-agent/pkg/traefik"
	"github.com/traefik/neo-agent/pkg/version"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
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
	flagCertsDir                = "certs-dir"
)

func main() {
	rand.Seed(time.Now().UnixNano())

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
				Name:     flagTraefikAddr,
				Usage:    "Address on which the Agent can reach Traefik",
				EnvVars:  []string{strcase.ToSNAKE(flagTraefikAddr)},
				Required: true,
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
				Name:    flagAuthServerReachableAddr,
				Usage:   "Address on which Traefik can reach the Agent auth server. Required when the automatic IP discovery fails",
				EnvVars: []string{strcase.ToSNAKE(flagAuthServerReachableAddr)},
			},
			&cli.StringFlag{
				Name:    flagAuthServerACPDir,
				Usage:   "Directory path containing Access Control Policy configurations",
				EnvVars: []string{strcase.ToSNAKE(flagAuthServerACPDir)},
				Value:   "./acps",
			},
			// NOTE: this flag is added for development and testing only. It will be replaced once we can fetch certificates from the platform.
			&cli.StringFlag{
				Name:    flagCertsDir,
				Usage:   "Directory path containing certificates",
				EnvVars: []string{strcase.ToSNAKE(flagCertsDir)},
				Value:   "./certs",
				Hidden:  true,
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

	traefikAddr := cliCtx.String(flagTraefikAddr)
	traefikClient, err := traefik.NewClient(traefikAddr)
	if err != nil {
		return fmt.Errorf("create Traefik client: %w", err)
	}

	listenAddr, reachableAddr := cliCtx.String(flagAuthServerListenAddr), cliCtx.String(flagAuthServerReachableAddr)
	if reachableAddr == "" {
		log.Debug().Msg("Using auto-discovery to find Agent reachable address")
		reachableAddr, err = getAgentReachableAddress(cliCtx.Context, traefikClient, listenAddr)
		if err != nil {
			return fmt.Errorf("get agent reachable address: %w. Consider using the `%s` flag", err, flagAuthServerReachableAddr)
		}
	}

	log.Info().Str("addr", reachableAddr).Msg("Using Agent reachable address")

	traefikManager, err := traefik.NewManager(cliCtx.Context, traefikClient)
	if err != nil {
		return fmt.Errorf("new Traefik manager: %w", err)
	}

	middlewareCfgBuilder := acp.NewMiddlewareConfigBuilder(traefikManager, reachableAddr)

	acpServer := acp.NewServer(listenAddr)
	acpWatcher := acp.NewWatcher(
		cliCtx.String(flagAuthServerACPDir),
		acpServer.UpdateHandler,
		middlewareCfgBuilder.UpdateConfig,
	)

	tlsCfgBuilder := certificate.NewTLSConfigBuilder(traefikManager)
	certificatesWatcher := certificate.NewWatcher(
		cliCtx.String(flagCertsDir),
		tlsCfgBuilder.UpdateConfig,
	)

	cfgWatcher := platform.NewConfigWatcher(15*time.Minute, platformClient)
	metricsMgr, metricsStore, err := newMetrics(token, platformURL, agentCfg.Metrics, cfgWatcher)
	if err != nil {
		return err
	}

	heartbeater := heartbeat.NewHeartbeater(platformClient)

	group, ctx := errgroup.WithContext(cliCtx.Context)
	group.Go(func() error {
		heartbeater.Run(ctx)
		return nil
	})

	group.Go(func() error {
		acpWatcher.Run(ctx)
		return nil
	})

	group.Go(func() error {
		return acpServer.Run(ctx)
	})

	group.Go(func() error {
		certificatesWatcher.Run(ctx)
		return nil
	})

	group.Go(func() error {
		traefikManager.Run(ctx)
		return nil
	})

	group.Go(func() error {
		return metricsMgr.Run(ctx, traefikAddr)
	})

	group.Go(func() error {
		return runAlerting(ctx, token, platformURL, metricsStore)
	})

	return group.Wait()
}

func getAgentReachableAddress(ctx context.Context, traefikClient *traefik.Client, listenAddr string) (string, error) {
	reachableIP, err := traefikClient.GetAgentReachableIP(ctx)
	if err != nil {
		return "", err
	}

	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("http://%s:%s", reachableIP, port), nil
}
