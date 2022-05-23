package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/docker/docker/api/types"
	eventtypes "github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/topology"
)

// Docker is a Docker client.
type Docker struct {
	client client.APIClient
}

// NewDocker creates Docker.
func NewDocker(dockerClient client.APIClient) *Docker {
	return &Docker{client: dockerClient}
}

// Watch watches docker events.
func (d Docker) Watch(ctx context.Context, clusterID string, fn func(map[string]*topology.Service)) error {
	f := filters.NewArgs()
	f.Add("type", "container")
	options := types.EventsOptions{
		Filters: f,
	}

	startStopHandle := func(_ eventtypes.Message) {
		services, err := d.getServices(ctx, clusterID)
		if err != nil {
			log.Error().Err(err).Send()
			return
		}

		fn(services)
	}

	startStopHandle(eventtypes.Message{})

	eventsc, errc := d.client.Events(ctx, options)
	for {
		select {
		case event := <-eventsc:
			if event.Action == "start" ||
				event.Action == "die" ||
				strings.HasPrefix(event.Action, "health_status") {
				startStopHandle(event)
			}
		case err := <-errc:
			if errors.Is(err, io.EOF) {
				log.Debug().Msg("Provider event stream closed")
			}
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

func (d Docker) getServices(ctx context.Context, clusterID string) (map[string]*topology.Service, error) {
	containers, err := d.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	services := make(map[string]*topology.Service)
	for _, container := range containers {
		containerInspect, err := d.client.ContainerInspect(ctx, container.ID)
		if err != nil {
			return nil, fmt.Errorf("inspect container %s: %w", container.ID, err)
		}

		if containerInspect.State != nil && containerInspect.State.Health != nil &&
			containerInspect.State.Health.Status != "" && containerInspect.State.Health.Status != "healthy" {
			log.Debug().Msg("Filtering unhealthy or starting container")
			continue
		}

		var ports []int
		for _, port := range container.Ports {
			ports = append(ports, int(port.PrivatePort))
		}

		info := d.getContainerInfo(ctx, containerInspect)
		if info == nil {
			continue
		}

		services[containerInspect.Name] = &topology.Service{
			Name:      strings.TrimPrefix(containerInspect.Name, "/"),
			ClusterID: clusterID,
			Container: info,
			Ports:     ports,
		}
	}

	return services, nil
}

func (d Docker) getContainerInfo(ctx context.Context, container types.ContainerJSON) *topology.Container {
	if container.HostConfig.NetworkMode.IsHost() {
		return &topology.Container{Name: container.Name, Networks: []string{"HOST"}}
	}

	if container.HostConfig.NetworkMode.IsContainer() {
		connectedContainer := container.HostConfig.NetworkMode.ConnectedContainer()
		containerInspect, err := d.client.ContainerInspect(ctx, connectedContainer)
		if err != nil {
			log.Warn().
				Str("container_name", container.Name).
				Str("connected_container", connectedContainer).
				Err(err).
				Msg("Unable to get IP address")

			return nil
		}

		container = containerInspect
	}

	if container.NetworkSettings != nil && len(container.NetworkSettings.Networks) > 0 {
		c := &topology.Container{Name: strings.TrimPrefix(container.Name, "/")}

		for network := range container.NetworkSettings.Networks {
			c.Networks = append(c.Networks, network)
		}

		return c
	}

	return nil
}

// GetIP gets container IP.
func (d Docker) GetIP(ctx context.Context, containerName, network string) (string, error) {
	container, err := d.client.ContainerInspect(ctx, containerName)
	if err != nil {
		return "", err
	}

	if container.HostConfig.NetworkMode.IsHost() {
		if network != "HOST" {
			return "", fmt.Errorf("the network mode %s is different from HOST", network)
		}

		if container.Node != nil && container.Node.IPAddress != "" {
			return container.Node.IPAddress, nil
		}

		if host, err := net.LookupHost("host.docker.internal"); err == nil {
			return host[0], nil
		}

		return "127.0.0.1", nil
	}

	if container.HostConfig.NetworkMode.IsContainer() {
		connectedContainer := container.HostConfig.NetworkMode.ConnectedContainer()
		containerInspect, err := d.client.ContainerInspect(ctx, connectedContainer)
		if err != nil {
			log.Error().
				Str("container_name", container.Name).
				Str("connected_container", connectedContainer).
				Err(err).
				Msg("Unable to get IP address")

			return "", nil
		}

		return getContainerIP(containerInspect, network)
	}

	return getContainerIP(container, network)
}

func getContainerIP(container types.ContainerJSON, network string) (string, error) {
	if container.NetworkSettings == nil {
		return "", fmt.Errorf("%s: no network settings", network)
	}

	for name, settings := range container.NetworkSettings.Networks {
		if network == name {
			return settings.IPAddress, nil
		}
	}

	return "", fmt.Errorf("%s: no IP address", network)
}
