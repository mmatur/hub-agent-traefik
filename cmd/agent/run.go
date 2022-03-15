package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/ettle/strcase"
	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/acp"
	"github.com/traefik/hub-agent-traefik/pkg/certificate"
	"github.com/traefik/hub-agent-traefik/pkg/heartbeat"
	"github.com/traefik/hub-agent-traefik/pkg/logger"
	"github.com/traefik/hub-agent-traefik/pkg/platform"
	"github.com/traefik/hub-agent-traefik/pkg/topology"
	"github.com/traefik/hub-agent-traefik/pkg/topology/state"
	topostore "github.com/traefik/hub-agent-traefik/pkg/topology/store"
	"github.com/traefik/hub-agent-traefik/pkg/traefik"
	"github.com/traefik/hub-agent-traefik/pkg/tunnel"
	"github.com/traefik/hub-agent-traefik/pkg/version"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

type runCmd struct {
	flags []cli.Flag
}

func newRunCmd() runCmd {
	return runCmd{
		flags: []cli.Flag{
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
				Usage:    "Address to advertise for Traefik to reach the Agent authentication server. Required when the automatic discovery fails",
				EnvVars:  []string{strcase.ToSNAKE(flagTraefikAddr)},
				Required: true,
			},
			&cli.StringFlag{
				Name:     flagHubToken,
				Usage:    "The token to use for Hub platform API calls",
				EnvVars:  []string{strcase.ToSNAKE(flagHubToken)},
				Required: true,
			},
			&cli.StringFlag{
				Name:    flagHubURL,
				Usage:   "The URL where to reach the Hub platform API",
				Value:   "https://platform.hub.traefik.io/agent",
				EnvVars: []string{strcase.ToSNAKE(flagHubURL)},
				Hidden:  true,
			},
			&cli.StringFlag{
				Name:    flagAuthServerListenAddr,
				Usage:   "Address on which the auth server listens for auth requests",
				EnvVars: []string{strcase.ToSNAKE(flagAuthServerListenAddr)},
				Value:   "0.0.0.0:80",
			},
			&cli.StringFlag{
				Name:    flagAuthServerAdvertiseAddr,
				Usage:   "Address on which Traefik can reach the Agent auth server. Required when the automatic IP discovery fails",
				EnvVars: []string{strcase.ToSNAKE(flagAuthServerAdvertiseAddr)},
			},
			&cli.StringFlag{
				Name:    flagAuthServerACPDir,
				Usage:   "Directory path containing Access Control Policy configurations",
				EnvVars: []string{strcase.ToSNAKE(flagAuthServerACPDir)},
				Value:   "/etc/hub-agent/acps/",
			},
		},
	}
}

func (r runCmd) build() *cli.Command {
	return &cli.Command{
		Name:   "run",
		Usage:  "Runs the Hub Agent",
		Flags:  r.flags,
		Action: r.runAgent,
	}
}

func (r runCmd) runAgent(cliCtx *cli.Context) error {
	logger.Setup(cliCtx.String(flagLogLevel), cliCtx.String(flagLogFormat))

	version.Log()

	platformURL, token := cliCtx.String(flagHubURL), cliCtx.String(flagHubToken)
	platformClient, err := platform.NewClient(platformURL, token)
	if err != nil {
		return fmt.Errorf("new platform client: %w", err)
	}

	agentCfg, clusterID, err := initAgent(cliCtx.Context, platformClient)
	if err != nil {
		return fmt.Errorf("get platform config: %w", err)
	}

	traefikAddr := cliCtx.String(flagTraefikAddr)
	traefikClient, err := traefik.NewClient(traefikAddr)
	if err != nil {
		return fmt.Errorf("create Traefik client: %w", err)
	}

	listenAddr, reachableAddr := cliCtx.String(flagAuthServerListenAddr), cliCtx.String(flagAuthServerAdvertiseAddr)
	if reachableAddr == "" {
		log.Debug().Msg("Using auto-discovery to find Agent reachable address")
		reachableAddr, err = getAgentReachableAddress(cliCtx.Context, traefikClient, listenAddr)
		if err != nil {
			return fmt.Errorf("get agent reachable address: %w. Consider using the `%s` flag", err, flagAuthServerAdvertiseAddr)
		}
	}

	log.Info().Str("addr", reachableAddr).Msg("Using Agent reachable address")

	traefikManager, err := traefik.NewManager(cliCtx.Context, traefikClient)
	if err != nil {
		return fmt.Errorf("new Traefik manager: %w", err)
	}

	middlewareCfgBuilder := acp.NewMiddlewareConfigBuilder(traefikManager, reachableAddr)

	acpServer := acp.NewServer(listenAddr)
	routerUpdater := acp.NewRouterUpdater(traefikManager, agentCfg.AccessControl.MaxSecuredRoutes)

	fetcher := state.NewFetcher(clusterID, traefikManager)
	acpWatcher := acp.NewWatcher(
		cliCtx.String(flagAuthServerACPDir),
		[]acp.UpdatedACPFunc{
			acpServer.UpdateHandler,
			middlewareCfgBuilder.UpdateConfig,
			fetcher.UpdateACP,
			routerUpdater.UpdateACP,
		},
	)

	certClient, err := certificate.NewClient(platformURL, token)
	if err != nil {
		return fmt.Errorf("create certificate client: %w", err)
	}
	tlsManager := certificate.NewTLSConfigBuilder(traefikManager, certClient)
	traefikManager.AddUpdateListener(tlsManager.ObtainCertificates)
	traefikManager.AddUpdateListener(routerUpdater.UpdateDynamic)

	store, err := topostore.New(cliCtx.Context, topostore.Config{
		TopologyConfig: agentCfg.Topology,
		Token:          token,
	})
	if err != nil {
		return fmt.Errorf("create topology store: %w", err)
	}

	topologyWatcher := topology.NewWatcher(fetcher, store)
	cfgWatcher := platform.NewConfigWatcher(15*time.Minute, platformClient)
	metricsMgr, metricsStore, err := newMetrics(token, platformURL, agentCfg.Metrics, cfgWatcher)
	if err != nil {
		return err
	}

	tunnelClient, err := tunnel.NewClient(platformURL, token)
	if err != nil {
		return fmt.Errorf("create tunnel client: %w", err)
	}

	addr, err := url.Parse(traefikAddr)
	if err != nil {
		return fmt.Errorf("parse traefik addr: %w", err)
	}
	host, _, err := net.SplitHostPort(addr.Host)
	if err != nil {
		return fmt.Errorf("split host port for traefik addr: %w", err)
	}
	tunnelManager := tunnel.NewManager(tunnelClient, host, token)

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
		tlsManager.Run(ctx)
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

	group.Go(func() error {
		topologyWatcher.Start(ctx)
		return nil
	})

	group.Go(func() error {
		tunnelManager.Run(ctx)
		return nil
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

func initAgent(ctx context.Context, platformClient *platform.Client) (platform.Config, string, error) {
	clusterID, err := platformClient.Link(ctx)
	if err != nil {
		return platform.Config{}, "", fmt.Errorf("link agent: %w", err)
	}

	agentCfg, err := platformClient.GetConfig(ctx)
	if err != nil {
		return platform.Config{}, "", fmt.Errorf("fetch agent config: %w", err)
	}

	return agentCfg, clusterID, nil
}
