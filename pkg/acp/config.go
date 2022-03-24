package acp

import (
	"errors"

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

// Validate validates ACP config.
func (c Config) Validate() error {
	if c.JWT == nil && c.BasicAuth == nil && c.DigestAuth == nil {
		return errors.New("one of jwt, basicAuth, digestAuth authentication method must be set")
	}

	return nil
}
