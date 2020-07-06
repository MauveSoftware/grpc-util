package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
)

func LoadTLSCert(cfg *TLSConfig) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, errors.Wrap(err, "could not load certificate")
	}

	ca, err := ioutil.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, errors.Wrap(err, "could not load CA certificate")
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(ca) {
		return nil, errors.Wrap(err, "could not add CA certificate to chain")
	}

	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    capool,
		RootCAs:      capool,
	}, nil
}

func isInAllowedCNs(commonName string, allowed []string) bool {
	for _, allowPattern := range allowed {
		if matchesAllowPattern(commonName, allowPattern) {
			return true
		}
	}

	return false
}

func matchesAllowPattern(commonName, allowPattern string) bool {
	if allowPattern == "*" {
		return true
	}

	if strings.ToLower(allowPattern) == strings.ToLower(commonName) {
		return true
	}

	if strings.HasPrefix(allowPattern, "*.") {
		suffix := strings.ToLower(allowPattern[2:])
		return strings.HasSuffix(strings.ToLower(commonName), suffix)
	}

	return false
}
