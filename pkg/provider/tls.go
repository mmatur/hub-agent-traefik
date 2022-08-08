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

package provider

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ClientTLS holds TLS specific configurations as client
// CA, Cert and Key can be either path or file contents.
type ClientTLS struct {
	CA                 string
	CAOptional         bool
	Cert               string
	Key                string
	InsecureSkipVerify bool
}

// CreateTLSConfig creates a TLS config from ClientTLS structures.
func (c *ClientTLS) CreateTLSConfig() (*tls.Config, error) {
	if c == nil {
		return nil, nil
	}

	clientAuth, caPool, err := c.getCA()
	if err != nil {
		return nil, err
	}

	hasCert := len(c.Cert) > 0
	hasKey := len(c.Key) > 0

	if hasCert != hasKey {
		return nil, errors.New("both TLS cert and key must be defined")
	}

	if !hasCert || !hasKey {
		return &tls.Config{
			RootCAs:            caPool,
			InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // it's a valid option
			ClientAuth:         clientAuth,
		}, nil
	}

	cert, err := loadKeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // it's a valid option
		ClientAuth:         clientAuth,
	}, nil
}

func (c *ClientTLS) getCA() (tls.ClientAuthType, *x509.CertPool, error) {
	if c.CA == "" {
		return tls.NoClientCert, nil, nil
	}

	var ca []byte
	if _, errCA := os.Stat(c.CA); errCA == nil {
		var err error
		ca, err = os.ReadFile(c.CA)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to read CA. %w", err)
		}
	} else {
		ca = []byte(c.CA)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(ca) {
		return 0, nil, errors.New("failed to parse CA")
	}

	if c.CAOptional {
		return tls.VerifyClientCertIfGiven, caPool, nil
	}

	return tls.RequireAndVerifyClientCert, caPool, nil
}

func loadKeyPair(cert, key string) (tls.Certificate, error) {
	keyPair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err == nil {
		return keyPair, nil
	}

	_, err = os.Stat(cert)
	if err != nil {
		return tls.Certificate{}, errors.New("cert file does not exist")
	}

	_, err = os.Stat(key)
	if err != nil {
		return tls.Certificate{}, errors.New("key file does not exist")
	}

	keyPair, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return keyPair, nil
}
