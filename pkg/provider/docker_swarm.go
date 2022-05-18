package provider

import (
	"context"
	"fmt"
	"net"
	"strconv"
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
	client   *client.Client
	interval time.Duration
}

// NewDockerSwarm creates DockerSwarm.
func NewDockerSwarm(dockerClient *client.Client, interval time.Duration) *DockerSwarm {
	return &DockerSwarm{client: dockerClient, interval: interval}
}

// Watch watches docker events.
func (d DockerSwarm) Watch(ctx context.Context, clusterID string, fn func(map[string]*topology.Service)) error {
	ticker := time.NewTicker(d.interval)

	log.Info().Str("cluster_id", clusterID).Msg("watch")

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

		svc.IPs = d.getServiceIPs(loggerSvc.WithContext(ctx), service, networkMap)

		services[svc.Name] = svc

		serviceIDFilter := filters.NewArgs()
		serviceIDFilter.Add("service", service.ID)
		serviceIDFilter.Add("desired-state", "running")
		tasks, err := d.client.TaskList(ctx, dockertypes.TaskListOptions{Filters: serviceIDFilter})
		if err != nil {
			return nil, fmt.Errorf("list tasks: %w", err)
		}

		for _, task := range tasks {
			if task.Status.State != swarmtypes.TaskStateRunning {
				continue
			}

			tService := &topology.Service{
				Name:      svc.Name + "." + strconv.Itoa(task.Slot),
				ClusterID: clusterID,
				Ports:     svc.Ports,
			}

			if service.Spec.Mode.Global != nil {
				tService.Name = svc.Name + "." + task.ID
			}

			loggerTsk := log.With().Str("cluster_id", clusterID).
				Str("service_id", service.ID).
				Str("service_name", tService.Name).
				Str("task_id", task.ID).
				Logger()

			if task.NetworksAttachments != nil {
				tService.IPs = d.getTaskIPs(loggerTsk.WithContext(ctx), task, networkMap)

				services[tService.Name] = tService
			}
		}
	}

	return services, nil
}

func (d DockerSwarm) getTaskIPs(ctx context.Context, task swarmtypes.Task, networkMap map[string]*dockertypes.NetworkResource) []string {
	logger := log.Ctx(ctx)

	var ips []string
	for _, virtualIP := range task.NetworksAttachments {
		networkService, present := networkMap[virtualIP.Network.ID]
		if !present {
			continue
		}

		if networkService.Ingress {
			continue
		}

		if len(virtualIP.Addresses) == 0 {
			logger.Debug().Str("network_id", virtualIP.Network.ID).Msg("No IP addresses found for network")
			continue
		}

		// Not sure about this next loop - when would a task have multiple IP's for the same network?
		for _, addr := range virtualIP.Addresses {
			ip, _, _ := net.ParseCIDR(addr)

			ips = append(ips, networkService.Name+":"+ip.String())
		}
	}

	return ips
}

func (d DockerSwarm) getServiceIPs(ctx context.Context, service swarmtypes.Service, networkMap map[string]*dockertypes.NetworkResource) []string {
	logger := log.Ctx(ctx)

	var ips []string
	if service.Spec.EndpointSpec != nil {
		switch service.Spec.EndpointSpec.Mode {
		case swarmtypes.ResolutionModeDNSRR:
			logger.Debug().Msgf("Ignored %s endpoint-mode not supported", swarmtypes.ResolutionModeDNSRR)
		case swarmtypes.ResolutionModeVIP:
			for _, virtualIP := range service.Endpoint.VirtualIPs {
				networkService := networkMap[virtualIP.NetworkID]

				if networkService.Ingress {
					continue
				}

				if networkService == nil {
					logger.Debug().Str("network_id", virtualIP.NetworkID).Msg("Network not found")
					continue
				}

				if virtualIP.Addr == "" {
					logger.Debug().Str("network_id", virtualIP.NetworkID).Msg("No virtual IPs found in network")
					continue
				}

				ip, _, _ := net.ParseCIDR(virtualIP.Addr)

				ips = append(ips, networkService.Name+":"+ip.String())
			}
		}
	}

	return ips
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
