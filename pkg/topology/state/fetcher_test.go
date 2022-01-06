package state

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/types"
	"github.com/traefik/neo-agent/pkg/acp"
	"github.com/traefik/neo-agent/pkg/acp/basicauth"
	"github.com/traefik/neo-agent/pkg/acp/digestauth"
	"github.com/traefik/neo-agent/pkg/acp/jwt"
	"github.com/traefik/neo-agent/pkg/traefik"
)

func TestFetcher_FetchState(t *testing.T) {
	clusterID := "clusterID"

	tests := []struct {
		desc        string
		dynCfg      traefik.RunTimeRepresentation
		wantCluster *Cluster
	}{
		{
			desc:   "empty dynamic",
			dynCfg: traefik.RunTimeRepresentation{},
			wantCluster: &Cluster{
				ID: clusterID,
				Overview: Overview{
					IngressControllerTypes: []string{"traefik"},
				},
				IngressRoutes: map[string]*IngressRoute{},
				Services:      map[string]*Service{},
				IngressControllers: map[string]*IngressController{
					"traefik@traefik": {
						Name: "traefik@traefik",
						Kind: "Multiplatform",
						Type: "traefik",
					},
				},
				AccessControlPolicies: map[string]*AccessControlPolicy{
					"my-acps@plugin-hub-provider": {
						Name:      "my-acps@plugin-hub-provider",
						ClusterID: clusterID,
						Method:    "jwt",
						JWT: &AccessControlPolicyJWT{
							SigningSecret: "redacted",
						},
					},
				},
			},
		},
		{
			desc: "build cluster from runtime representation",
			dynCfg: traefik.RunTimeRepresentation{
				Routers: map[string]*dynamic.Router{
					"whoami@docker": {
						EntryPoints: []string{"entrypoint"},
						Middlewares: []string{"my-acps@plugin-hub-provider"},
						Service:     "whoami-whoami",
						Rule:        "Host(`whoami.localhost`)",
						TLS: &dynamic.RouterTLSConfig{
							Options: "tlsOptionName",
							Domains: []types.Domain{
								{
									Main: "whoami.local",
									SANs: []string{"whoami.localhost"},
								},
							},
						},
					},
					"whoami-file@docker": {
						EntryPoints: []string{"entrypoint"},
						Service:     "whoami-whoami@file",
						Rule:        "Host(`whoami-file.localhost`)",
					},
				},
				Services: map[string]*dynamic.Service{
					"whoami-whoami@docker": {
						LoadBalancer: &dynamic.ServersLoadBalancer{},
					},
					"whoami-whoami@file": {
						Weighted: &dynamic.WeightedRoundRobin{},
					},
					"whoami-mirroring@file": {
						Mirroring: &dynamic.Mirroring{},
					},
				},
			},
			wantCluster: &Cluster{
				ID: clusterID,
				Overview: Overview{
					IngressCount:           2,
					ServiceCount:           3,
					IngressControllerTypes: []string{"traefik"},
				},
				IngressRoutes: map[string]*IngressRoute{
					"whoami@docker": {
						ResourceMeta: ResourceMeta{Kind: "Router", Name: "whoami@docker"},
						IngressMeta: IngressMeta{
							ClusterID:      clusterID,
							ControllerType: "traefik",
							Annotations: map[string]string{
								"hub.traefik.io/access-control-policy": "my-acps@plugin-hub-provider",
							},
						},
						TLS: &IngressRouteTLS{
							Domains: []types.Domain{
								{
									Main: "whoami.local",
									SANs: []string{"whoami.localhost"},
								},
							},
							Options: &TLSOptionRef{Name: "tlsOptionName"},
						},
						Routes: []Route{
							{
								Match:    "Host(`whoami.localhost`)",
								Services: []RouteService{{Name: "whoami-whoami@docker"}},
							},
						},
						Services: []string{"whoami-whoami@docker"},
					},
					"whoami-file@docker": {
						ResourceMeta: ResourceMeta{Kind: "Router", Name: "whoami-file@docker"},
						IngressMeta: IngressMeta{
							ClusterID:      clusterID,
							ControllerType: "traefik",
						},
						Routes: []Route{
							{
								Match:    "Host(`whoami-file.localhost`)",
								Services: []RouteService{{Name: "whoami-whoami@file"}},
							},
						},
						Services: []string{"whoami-whoami@file"},
					},
				},
				Services: map[string]*Service{
					"whoami-whoami@docker": {
						Name:      "whoami-whoami@docker",
						Type:      "TraefikLoadBalancer",
						ClusterID: clusterID,
					},
					"whoami-whoami@file": {
						Name:      "whoami-whoami@file",
						Type:      "TraefikWRR",
						ClusterID: clusterID,
					},
					"whoami-mirroring@file": {
						Name:      "whoami-mirroring@file",
						Type:      "TraefikMirroring",
						ClusterID: clusterID,
					},
				},
				IngressControllers: map[string]*IngressController{
					"traefik@traefik": {
						Name: "traefik@traefik",
						Kind: "Multiplatform",
						Type: "traefik",
					},
				},
				AccessControlPolicies: map[string]*AccessControlPolicy{
					"my-acps@plugin-hub-provider": {
						Name:      "my-acps@plugin-hub-provider",
						ClusterID: clusterID,
						Method:    "jwt",
						JWT: &AccessControlPolicyJWT{
							SigningSecret: "redacted",
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			mux := http.NewServeMux()
			mux.HandleFunc("/api/rawdata", func(rw http.ResponseWriter, req *http.Request) {
				rw.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(rw).Encode(&test.dynCfg)
				require.NoError(t, err)
			})
			mux.HandleFunc("/state", func(rw http.ResponseWriter, req *http.Request) {
				rw.Header().Set("Content-Type", "application/json")
				st := struct {
					PluginName         string `json:"pluginName"`
					LastConfigUnixNano int64  `json:"lastConfigUnixNano"`
				}{
					PluginName:         "plugin-hub-provider",
					LastConfigUnixNano: 0,
				}

				err := json.NewEncoder(rw).Encode(&st)
				require.NoError(t, err)
			})

			srv := httptest.NewServer(mux)

			traefikClient, err := traefik.NewClient(srv.URL)
			require.NoError(t, err)

			ctx := context.Background()
			traefikManager, err := traefik.NewManager(ctx, traefikClient)
			require.NoError(t, err)

			fetcher := NewFetcher(clusterID, traefikManager)
			fetcher.acps = map[string]*acp.Config{
				"my-acps": {
					JWT: &jwt.Config{
						SigningSecret: "secret",
					},
				},
			}

			cluster, err := fetcher.FetchState(ctx)
			require.NoError(t, err)

			assert.Equal(t, test.wantCluster, cluster)
		})
	}
}

func TestFetcher_FetchState_HandleAccessControlPolicies(t *testing.T) {
	tests := []struct {
		desc           string
		acps           map[string]*acp.Config
		wantACPCluster map[string]*AccessControlPolicy
	}{
		{
			desc: "Empty",
			acps: map[string]*acp.Config{
				"my-acps": {
					JWT: &jwt.Config{
						SigningSecret: "secret",
					},
				},
			},
			wantACPCluster: map[string]*AccessControlPolicy{
				"my-acps@plugin-hub-provider": {
					Name:      "my-acps@plugin-hub-provider",
					ClusterID: "clusterID",
					Method:    "jwt",
					JWT: &AccessControlPolicyJWT{
						SigningSecret: "redacted",
					},
				},
			},
		},
		{
			desc: "JWT access control policy",
			acps: map[string]*acp.Config{
				"my-acps": {
					JWT: &jwt.Config{
						SigningSecret:              "titi",
						SigningSecretBase64Encoded: true,
						PublicKey:                  "toto",
						JWKsFile:                   "tata",
						JWKsURL:                    "tete",
						StripAuthorizationHeader:   false,
						ForwardHeaders:             map[string]string{"Titi": "toto", "Toto": "titi"},
						TokenQueryKey:              "token",
						Claims:                     "iss=titi",
					},
				},
			},
			wantACPCluster: map[string]*AccessControlPolicy{
				"my-acps@plugin-hub-provider": {
					Name:      "my-acps@plugin-hub-provider",
					ClusterID: "clusterID",
					Method:    "jwt",
					JWT: &AccessControlPolicyJWT{
						SigningSecret:              "redacted",
						JWKsFile:                   "tata",
						JWKsURL:                    "tete",
						StripAuthorizationHeader:   false,
						PublicKey:                  "toto",
						SigningSecretBase64Encoded: true,
						ForwardHeaders:             map[string]string{"Titi": "toto", "Toto": "titi"},
						TokenQueryKey:              "token",
						Claims:                     "iss=titi",
					},
				},
			},
		},
		{
			desc: "Obfuscation doesn't run when fields are empty",
			acps: map[string]*acp.Config{
				"my-acps": {
					JWT: &jwt.Config{
						Claims: "iss=titi",
					},
				},
			},
			wantACPCluster: map[string]*AccessControlPolicy{
				"my-acps@plugin-hub-provider": {
					Name:      "my-acps@plugin-hub-provider",
					ClusterID: "clusterID",
					Method:    "jwt",
					JWT: &AccessControlPolicyJWT{
						Claims: "iss=titi",
					},
				},
			},
		},
		{
			desc: "Basic Auth access control policy",
			acps: map[string]*acp.Config{
				"my-acps": {
					BasicAuth: &basicauth.Config{
						Users:                    basicauth.Users([]string{"toto:secret", "titi:secret"}),
						Realm:                    "realm",
						StripAuthorizationHeader: true,
					},
				},
			},
			wantACPCluster: map[string]*AccessControlPolicy{
				"my-acps@plugin-hub-provider": {
					Name:      "my-acps@plugin-hub-provider",
					ClusterID: "clusterID",
					Method:    "basicauth",
					BasicAuth: &AccessControlPolicyBasicAuth{
						Users:                    "toto:redacted,titi:redacted",
						Realm:                    "realm",
						StripAuthorizationHeader: true,
					},
				},
			},
		},
		{
			desc: "Digest Auth access control policy",
			acps: map[string]*acp.Config{
				"my-acps": {
					DigestAuth: &digestauth.Config{
						Users:                    basicauth.Users([]string{"toto:realm:secret", "titi:realm:secret"}),
						Realm:                    "myrealm",
						StripAuthorizationHeader: true,
					},
				},
			},
			wantACPCluster: map[string]*AccessControlPolicy{
				"my-acps@plugin-hub-provider": {
					Name:      "my-acps@plugin-hub-provider",
					ClusterID: "clusterID",
					Method:    "digestauth",
					DigestAuth: &AccessControlPolicyDigestAuth{
						Users:                    "toto:realm:redacted,titi:realm:redacted",
						Realm:                    "myrealm",
						StripAuthorizationHeader: true,
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			mux := http.NewServeMux()
			mux.HandleFunc("/api/rawdata", func(rw http.ResponseWriter, req *http.Request) {
				rw.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(rw).Encode(&traefik.RunTimeRepresentation{})
				require.NoError(t, err)
			})
			mux.HandleFunc("/state", func(rw http.ResponseWriter, req *http.Request) {
				rw.Header().Set("Content-Type", "application/json")
				st := struct {
					PluginName         string `json:"pluginName"`
					LastConfigUnixNano int64  `json:"lastConfigUnixNano"`
				}{
					PluginName:         "plugin-hub-provider",
					LastConfigUnixNano: 0,
				}

				err := json.NewEncoder(rw).Encode(&st)
				require.NoError(t, err)
			})

			srv := httptest.NewServer(mux)

			traefikClient, err := traefik.NewClient(srv.URL)
			require.NoError(t, err)

			ctx := context.Background()
			traefikManager, err := traefik.NewManager(ctx, traefikClient)
			require.NoError(t, err)

			fetcher := NewFetcher("clusterID", traefikManager)
			fetcher.acps = test.acps

			cluster, err := fetcher.FetchState(context.Background())
			require.NoError(t, err)

			wantCluster := &Cluster{
				ID: "clusterID",
				Overview: Overview{
					IngressControllerTypes: []string{"traefik"},
				},
				IngressRoutes: map[string]*IngressRoute{},
				Services:      map[string]*Service{},
				IngressControllers: map[string]*IngressController{
					"traefik@traefik": {
						Name: "traefik@traefik",
						Kind: "Multiplatform",
						Type: "traefik",
					},
				},
				AccessControlPolicies: test.wantACPCluster,
			}

			assert.Equal(t, wantCluster, cluster)
		})
	}
}
