package provider

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	swarmtypes "github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/versions"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/topology"
)

// DockerSwarm is a DockerSwarm client.
type DockerSwarm struct {
	client   client.APIClient
	interval time.Duration
}

// NewDockerSwarm creates DockerSwarm.
func NewDockerSwarm(dockerClient client.APIClient, interval time.Duration) *DockerSwarm {
	return &DockerSwarm{client: dockerClient, interval: interval}
}

// Watch watches docker events.
func (d DockerSwarm) Watch(ctx context.Context, clusterID string, fn func(map[string]*topology.Service)) error {
	ticker := time.NewTicker(d.interval)

	log.Info().Str("cluster_id", clusterID).Msg("watch")

	services, err := d.getServices(ctx, clusterID)
	if err == nil {
		fn(services)
	}

	go func(ctx context.Context) {
		for {
			select {
			case <-ticker.C:
				services, err := d.getServices(ctx, clusterID)
				if err != nil {
					log.Error().Err(err).Msg("Failed to list services for docker")
					continue
				}

				fn(services)

			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}(ctx)

	<-ctx.Done()

	return nil
}

func (d DockerSwarm) getServices(ctx context.Context, clusterID string) (map[string]*topology.Service, error) {
	logger := log.With().Str("cluster_id", clusterID).Logger()

	networkMap, err := d.getNetworks(ctx)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to network inspect on client for Docker")
		return nil, fmt.Errorf("get networks: %w", err)
	}

	containers, err := d.client.ServiceList(ctx, dockertypes.ServiceListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	services := make(map[string]*topology.Service)
	for _, service := range containers {
		svc := &topology.Service{
			Name:      service.Spec.Annotations.Name,
			ClusterID: clusterID,
		}

		loggerSvc := log.With().Str("cluster_id", clusterID).
			Str("service_id", service.ID).
			Str("service_name", svc.Name).
			Logger()

		for _, port := range service.Endpoint.Ports {
			svc.Ports = append(svc.Ports, int(port.TargetPort))
		}

		serviceInfo := d.getServiceInfo(loggerSvc.WithContext(ctx), service, networkMap)
		if serviceInfo == nil {
			continue
		}

		svc.Container = serviceInfo
		services[svc.Name] = svc
	}

	return services, nil
}

func (d DockerSwarm) getServiceInfo(ctx context.Context, service swarmtypes.Service, networkMap map[string]*dockertypes.NetworkResource) *topology.Container {
	logger := log.Ctx(ctx)

	if service.Spec.EndpointSpec == nil {
		return nil
	}

	switch service.Spec.EndpointSpec.Mode {
	case swarmtypes.ResolutionModeDNSRR:
		logger.Debug().Msgf("Ignored %s endpoint-mode not supported", swarmtypes.ResolutionModeDNSRR)
	case swarmtypes.ResolutionModeVIP:
		c := &topology.Container{Name: strings.TrimPrefix(service.Spec.Name, "/")}

		for _, virtualIP := range service.Endpoint.VirtualIPs {
			networkService := networkMap[virtualIP.NetworkID]
			if networkService == nil {
				logger.Debug().Str("network_id", virtualIP.NetworkID).Msg("Network not found")
				continue
			}

			if networkService.Ingress {
				continue
			}

			if virtualIP.Addr == "" {
				logger.Debug().Str("network_id", virtualIP.NetworkID).Msg("No virtual IPs found in network")
				continue
			}

			ip, _, err := net.ParseCIDR(virtualIP.Addr)
			if err != nil || ip == nil {
				continue
			}

			c.Networks = append(c.Networks, networkService.Name)
		}

		if len(c.Networks) > 0 {
			return c
		}
	}

	return nil
}

func (d DockerSwarm) getNetworks(ctx context.Context) (map[string]*dockertypes.NetworkResource, error) {
	serverVersion, err := d.client.ServerVersion(ctx)
	if err != nil {
		return nil, err
	}

	networkListArgs := filters.NewArgs()
	// https://docs.docker.com/engine/api/v1.29/#tag/Network (Docker 17.06)
	if versions.GreaterThanOrEqualTo(serverVersion.APIVersion, "1.29") {
		networkListArgs.Add("scope", "swarm")
	} else {
		networkListArgs.Add("driver", "overlay")
	}

	networkList, err := d.client.NetworkList(ctx, dockertypes.NetworkListOptions{Filters: networkListArgs})
	if err != nil {
		return nil, fmt.Errorf("network list: %w", err)
	}

	networkMap := make(map[string]*dockertypes.NetworkResource)
	for _, network := range networkList {
		networkToAdd := network
		networkMap[network.ID] = &networkToAdd
	}

	return networkMap, nil
}

// GetIP gets service IP.
func (d DockerSwarm) GetIP(ctx context.Context, serviceName, network string) (string, error) {
	logger := log.Ctx(ctx)

	service, _, err := d.client.ServiceInspectWithRaw(ctx, serviceName, dockertypes.ServiceInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("service inspect: %w", err)
	}

	networkMap, err := d.getNetworks(ctx)
	if err != nil {
		return "", fmt.Errorf("get networks: %w", err)
	}

	if service.Spec.EndpointSpec == nil {
		return "", nil
	}

	switch service.Spec.EndpointSpec.Mode {
	case swarmtypes.ResolutionModeDNSRR:
		logger.Debug().Msgf("Ignored %s endpoint-mode not supported", swarmtypes.ResolutionModeDNSRR)
	case swarmtypes.ResolutionModeVIP:
		return getServiceIP(ctx, service, networkMap, network), nil
	}

	return "", nil
}

func getServiceIP(ctx context.Context, service swarmtypes.Service, networkMap map[string]*dockertypes.NetworkResource, network string) string {
	logger := log.Ctx(ctx)

	for _, virtualIP := range service.Endpoint.VirtualIPs {
		networkService := networkMap[virtualIP.NetworkID]

		if networkService == nil {
			logger.Debug().Str("network_id", virtualIP.NetworkID).Msg("Network not found")
			continue
		}

		if networkService.Ingress {
			continue
		}

		if virtualIP.Addr == "" {
			logger.Debug().Str("network_id", virtualIP.NetworkID).Msg("No virtual IPs found in network")
			continue
		}

		if networkService.Name != network {
			continue
		}

		ip, _, err := net.ParseCIDR(virtualIP.Addr)
		if err != nil || ip == nil {
			continue
		}

		return ip.String()
	}

	return ""
}
