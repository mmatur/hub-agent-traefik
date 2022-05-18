package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode"

	"github.com/docker/docker/api/types"
	eventtypes "github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-traefik/pkg/topology"
)

const (
	labelDockerComposeProject = "com.docker.compose.project"
	labelDockerComposeService = "com.docker.compose.service"
)

// Docker is a Docker client.
type Docker struct {
	client *client.Client
}

// NewDocker creates Docker.
func NewDocker(dockerClient *client.Client) *Docker {
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

		name := getServiceName(container)

		services[name] = &topology.Service{
			Name:      name,
			ClusterID: clusterID,
			IPs:       d.getIPs(ctx, containerInspect),
			Ports:     ports,
		}
	}

	return services, nil
}

func (d Docker) getIPs(ctx context.Context, container types.ContainerJSON) []string {
	if container.HostConfig.NetworkMode.IsHost() {
		if container.Node != nil && container.Node.IPAddress != "" {
			return []string{container.Node.IPAddress}
		}

		if host, err := net.LookupHost("host.docker.internal"); err == nil {
			return []string{host[0]}
		}

		return []string{"127.0.0.1"}
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

		return getNetworkIPs(containerInspect)
	}

	return getNetworkIPs(container)
}

func getNetworkIPs(container types.ContainerJSON) []string {
	var ips []string

	if container.NetworkSettings != nil {
		for network, settings := range container.NetworkSettings.Networks {
			ips = append(ips, network+":"+settings.IPAddress)
		}
	}

	return ips
}

func getServiceName(container types.Container) string {
	name := strings.Join(container.Names, "-")

	dcp, okp := container.Labels[labelDockerComposeProject]
	dcs, oks := container.Labels[labelDockerComposeService]
	if okp && oks {
		name = dcs + "_" + dcp
	}

	return normalize(name)
}

// normalize Replace all special chars with `-`.
func normalize(name string) string {
	fargs := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	}
	// get function
	return strings.Join(strings.FieldsFunc(name, fargs), "-")
}
