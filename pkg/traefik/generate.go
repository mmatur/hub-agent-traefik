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

package traefik

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// DefaultDomain Traefik domain for the default certificate.
const DefaultDomain = "TRAEFIK HUB AGENT DEFAULT CERT"

// DefaultCertificate generates random TLS certificates.
func DefaultCertificate() (*tls.Certificate, error) {
	randomBytes := make([]byte, 100)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	zBytes := sha256.Sum256(randomBytes)
	z := hex.EncodeToString(zBytes[:sha256.Size])
	domain := fmt.Sprintf("%s.%s.traefik.default", z[:32], z[32:])

	certPEM, keyPEM, err := KeyPair(domain, time.Time{})
	if err != nil {
		return nil, err
	}

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &certificate, nil
}

// KeyPair generates cert and key files.
func KeyPair(domain string, expiration time.Time) ([]byte, []byte, error) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivKey)})

	certPEM, err := PemCert(rsaPrivKey, domain, expiration)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// PemCert generates PEM cert file.
func PemCert(privKey *rsa.PrivateKey, domain string, expiration time.Time) ([]byte, error) {
	derBytes, err := derCert(privKey, expiration, domain)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

func derCert(privKey *rsa.PrivateKey, expiration time.Time, domain string) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	if expiration.IsZero() {
		expiration = time.Now().Add(365 * (24 * time.Hour))
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: DefaultDomain,
		},
		NotBefore: time.Now(),
		NotAfter:  expiration,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
}
