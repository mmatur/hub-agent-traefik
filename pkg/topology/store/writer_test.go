/*
Copyright (C) 2022 Traefik Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/hub-agent-traefik/pkg/topology"
)

const (
	commitCommand = "commit"
	pushCommand   = "push"
)

func TestWrite_GitNoChanges(t *testing.T) {
	tmpDir := t.TempDir()

	var (
		pushCallCount   int
		commitCallCount int
	)
	s := &Store{
		workingDir: tmpDir,
		gitExecutor: func(_ context.Context, _ string, _ bool, args ...string) (string, error) {
			switch args[0] {
			case pushCommand:
				pushCallCount++
			case commitCommand:
				commitCallCount++
				return "nothing to commit", errors.New("fake error")
			}

			return "", nil
		},
	}

	err := s.Write(context.Background(), &topology.Cluster{ID: "myclusterID"})
	require.NoError(t, err)

	assert.Equal(t, 1, commitCallCount)
	assert.Equal(t, 0, pushCallCount)
}

func TestWrite_GitChanges(t *testing.T) {
	tmpDir := t.TempDir()

	var pushCallCount int
	s := &Store{
		workingDir: tmpDir,
		gitExecutor: func(_ context.Context, _ string, _ bool, args ...string) (string, error) {
			if args[0] == pushCommand {
				pushCallCount++
			}
			return "", nil
		},
	}

	err := s.Write(context.Background(), &topology.Cluster{ID: "myclusterID"})
	require.NoError(t, err)

	assert.Equal(t, 1, pushCallCount)
}

func TestWrite_IngressRoutes(t *testing.T) {
	tmpDir := t.TempDir()

	testIngressRoute := &topology.IngressRoute{
		ResourceMeta: topology.ResourceMeta{
			Kind: "kind",
			Name: "name",
		},
		IngressMeta: topology.IngressMeta{
			ClusterID:      "cluster-id",
			ControllerType: "controller",
			Annotations: map[string]string{
				"foo": "bar",
			},
		},
		Routes: []topology.Route{
			{
				Match: "Host(`foo.com`)",
				Services: []topology.RouteService{
					{
						Name: "service",
					},
				},
			},
		},
		Services: []string{"service@namespace"},
	}

	var pushCallCount int
	s := &Store{
		workingDir: tmpDir,
		gitExecutor: func(_ context.Context, _ string, _ bool, args ...string) (string, error) {
			if args[0] == pushCommand {
				pushCallCount++
			}
			return "", nil
		},
	}

	err := s.Write(context.Background(), &topology.Cluster{
		IngressRoutes: map[string]*topology.IngressRoute{
			"name@namespace.kind.group": testIngressRoute,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, pushCallCount)

	got := readTopology(t, tmpDir)

	var gotIngRoute topology.IngressRoute
	err = json.Unmarshal(got["/Ingresses/name@namespace.kind.group.json"], &gotIngRoute)
	require.NoError(t, err)

	assert.Equal(t, testIngressRoute, &gotIngRoute)
}

func TestWrite_IngressControllers(t *testing.T) {
	tmpDir := t.TempDir()

	testController := &topology.IngressController{
		Name: "myctrl",
		Kind: "Multiplatform",
		Type: "traefik",
	}

	var pushCallCount int
	s := &Store{
		workingDir: tmpDir,
		gitExecutor: func(_ context.Context, _ string, _ bool, args ...string) (string, error) {
			if args[0] == pushCommand {
				pushCallCount++
			}
			return "", nil
		},
	}

	err := s.Write(context.Background(), &topology.Cluster{
		IngressControllers: map[string]*topology.IngressController{
			"myctrl@myns": testController,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, pushCallCount)

	got := readTopology(t, tmpDir)

	var gotCtrl topology.IngressController
	err = json.Unmarshal(got["/IngressControllers/myctrl@myns.json"], &gotCtrl)
	require.NoError(t, err)

	assert.Equal(t, testController, &gotCtrl)
}

func TestWrite_Overview(t *testing.T) {
	tmpDir := t.TempDir()

	testOverview := topology.Overview{
		IngressCount:           2,
		ServiceCount:           1,
		IngressControllerTypes: []string{"traefik"},
	}

	var pushCallCount int
	s := &Store{
		workingDir: tmpDir,
		gitExecutor: func(_ context.Context, _ string, _ bool, args ...string) (string, error) {
			if args[0] == pushCommand {
				pushCallCount++
			}
			return "", nil
		},
	}

	err := s.Write(context.Background(), &topology.Cluster{Overview: testOverview})
	require.NoError(t, err)

	assert.Equal(t, 1, pushCallCount)

	got := readTopology(t, tmpDir)

	var gotOverview topology.Overview
	err = json.Unmarshal(got["/Overview.json"], &gotOverview)
	require.NoError(t, err)

	assert.Equal(t, testOverview, gotOverview)
}

func readTopology(t *testing.T, dir string) map[string][]byte {
	t.Helper()

	result := make(map[string][]byte)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			if path == "./" {
				return nil
			}

			data, err := os.ReadFile(path)
			require.NoError(t, err)

			result[strings.TrimPrefix(path, dir)] = data
		}
		return nil
	})
	require.NoError(t, err)

	return result
}
