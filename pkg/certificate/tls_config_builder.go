package certificate

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
	"github.com/traefik/genconf/dynamic/types"
)

var hostRuleRegexp = regexp.MustCompile(`Host\(([^)]+)\)`)

// TraefikManager allows pushing dynamic configurations to a TraefikManager instance.
type TraefikManager interface {
	SetTLSConfig(cfg *dynamic.TLSConfiguration)
}

// CertClient allows managing certificates from the platform.
type CertClient interface {
	Obtain(domains []string) (Certificate, error)
}

// TLSConfigBuilder builds Traefik TLS configurations.
type TLSConfigBuilder struct {
	traefik TraefikManager

	certificates CertClient

	certsMu sync.RWMutex
	certs   map[string]Certificate
}

// NewTLSConfigBuilder returns a new TLSConfigBuilder.
func NewTLSConfigBuilder(traefik TraefikManager, client CertClient) *TLSConfigBuilder {
	return &TLSConfigBuilder{
		traefik:      traefik,
		certificates: client,
		certs:        make(map[string]Certificate),
	}
}

// Run runs the TLSConfigBuilder.
func (b *TLSConfigBuilder) Run(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.renewExpiringCertificates()
		case <-ctx.Done():
			return
		}
	}
}

func (b *TLSConfigBuilder) renewExpiringCertificates() {
	var (
		certs   []Certificate
		updated bool
	)

	b.certsMu.Lock()
	for domains, cert := range b.certs {
		// The stored certificate has not exceeded two third of its total lifetime
		// (90 days for let's encrypt), we can continue using it.
		if time.Now().Add(30 * 24 * time.Hour).Before(cert.NotAfter) {
			certs = append(certs, cert)
			continue
		}

		// Check if the certificate was renewed.
		newCert, err := b.certificates.Obtain(strings.Split(domains, ","))
		if err != nil {
			log.Error().Err(err).Str("domains", domains).Msg("Unable to renew certificate for domains")
			continue
		}

		// Certificate was not renewed yet.
		if newCert.NotAfter.Equal(cert.NotAfter) {
			continue
		}

		b.certs[domains] = newCert
		certs = append(certs, newCert)
		updated = true
	}
	b.certsMu.Unlock()

	// No certificates were renewed, no need to update configuration.
	if !updated {
		return
	}

	b.traefik.SetTLSConfig(toDynamic(certs))
}

// ErrMustRetry indicates all certificates were not issued correctly and another attempt is required.
var ErrMustRetry = errors.New("must retry")

// ObtainCertificates sets the Traefik TLS Configuration with the needed certificates.
func (b *TLSConfigBuilder) ObtainCertificates(cfg *dynamic.Configuration) error {
	var (
		certs     []Certificate
		mustRetry bool
	)
	addedCerts := make(map[string]struct{})

	for _, router := range cfg.HTTP.Routers {
		if router.TLS == nil || router.TLS.CertResolver != "traefik-hub" {
			continue
		}

		var domains [][]string
		if len(router.TLS.Domains) > 0 {
			domains = getDomainNames(router.TLS.Domains)
		} else {
			// If no Domains are defined, try to deduce it from the Host rule.
			ruleDomains := parseDomains(router.Rule)
			if len(ruleDomains) == 0 {
				continue
			}

			domains = [][]string{ruleDomains}
		}

		if len(domains) == 0 {
			continue
		}

		platformCertificates, errs := b.getPlatformCertificates(domains)
		for _, err := range errs {
			mustRetry = true
			if errors.Is(err, ErrCertIssuancePending) {
				log.Debug().Str("status", err.Error()).Send()
				continue
			}

			log.Error().Err(err).Msg("Failed to get certificate from platform")
		}

		for _, cert := range platformCertificates {
			if _, ok := addedCerts[certKey(cert.Domains)]; ok {
				continue
			}
			addedCerts[certKey(cert.Domains)] = struct{}{}
			certs = append(certs, cert)
		}
	}

	b.traefik.SetTLSConfig(toDynamic(certs))

	if mustRetry {
		return ErrMustRetry
	}
	return nil
}

func getDomainNames(domains []types.Domain) [][]string {
	uniqDomains := make(map[string]struct{})
	var result [][]string

	for _, domain := range domains {
		sans := append([]string{domain.Main}, domain.SANs...)

		var domainNames []string
		for _, san := range sans {
			if _, ok := uniqDomains[san]; ok {
				continue
			}
			uniqDomains[san] = struct{}{}
			domainNames = append(domainNames, san)
		}

		sort.Strings(domainNames)
		result = append(result, domainNames)
	}

	return result
}

func parseDomains(rule string) []string {
	var domains []string
	for _, matches := range hostRuleRegexp.FindAllStringSubmatch(rule, -1) {
		for _, match := range matches[1:] {
			sanitizedDomains := strings.NewReplacer("`", "", " ", "").Replace(match)

			domains = append(domains, strings.Split(sanitizedDomains, ",")...)
		}
	}

	return domains
}

func (b *TLSConfigBuilder) getPlatformCertificates(domains [][]string) ([]Certificate, []error) {
	var (
		certs []Certificate
		errs  []error
	)

	for _, sans := range domains {
		key := certKey(sans)

		b.certsMu.Lock()
		if cert, ok := b.certs[key]; ok {
			log.Debug().Strs("domains", cert.Domains).Msg("Certificate already in cache")
			certs = append(certs, cert)
			b.certsMu.Unlock()
			continue
		}
		b.certsMu.Unlock()

		log.Debug().Strs("domains", sans).Msg("Requesting certificate to the platform")
		cert, err := b.certificates.Obtain(sans)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w for domains %v", err, sans))
			continue
		}

		b.certsMu.Lock()
		b.certs[key] = cert
		b.certsMu.Unlock()

		log.Debug().Msg("Successful obtain certificate from the platform")
		certs = append(certs, cert)
	}

	return certs, errs
}

func certKey(domains []string) string {
	sort.Strings(domains)
	return strings.Join(domains, ",")
}

func toDynamic(certs []Certificate) *dynamic.TLSConfiguration {
	certAndStores := make([]*tls.CertAndStores, 0, len(certs))
	for _, cert := range certs {
		certAndStores = append(certAndStores, &tls.CertAndStores{
			Certificate: tls.Certificate{
				CertFile: string(cert.Certificate),
				KeyFile:  string(cert.PrivateKey),
			},
		})
	}

	return &dynamic.TLSConfiguration{Certificates: certAndStores}
}
