package main

import (
	"context"

	"github.com/traefik/hub-agent-traefik/pkg/topology"
)

type providerMock struct{}

func (m providerMock) Watch(ctx context.Context, clusterID string, fn func(map[string]*topology.Service)) error {
	return nil
}

func (m providerMock) GetIP(ctx context.Context, containerName, network string) (string, error) {
	return "127.0.0.1", nil
}
