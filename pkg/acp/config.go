package acp

import (
	"github.com/traefik/hub-agent-traefik/pkg/acp/basicauth"
	"github.com/traefik/hub-agent-traefik/pkg/acp/digestauth"
	"github.com/traefik/hub-agent-traefik/pkg/acp/jwt"
)

// Config is the configuration of an Access Control Policy. It is used to set up ACP handlers.
type Config struct {
	JWT        *jwt.Config
	BasicAuth  *basicauth.Config  `yaml:"basicAuth"`
	DigestAuth *digestauth.Config `yaml:"digestAuth"`

	Ingresses []string `json:"ingresses"`
}
