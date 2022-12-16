package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// CertificatesFromContext extracts x509 certificate information from given context
func CertificatesFromContext(ctx context.Context) []*x509.Certificate {
	if p, ok := peer.FromContext(ctx); ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			return mtls.State.PeerCertificates
		}
	}

	return []*x509.Certificate{}
}

func loadTLSCert(cfg *TLSConfig) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, errors.Wrap(err, "could not load certificate")
	}

	ca, err := os.ReadFile(cfg.CAFile)
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

	if strings.EqualFold(allowPattern, commonName) {
		return true
	}

	if strings.HasPrefix(allowPattern, "*.") {
		suffix := strings.ToLower(allowPattern[2:])
		return strings.HasSuffix(strings.ToLower(commonName), suffix)
	}

	return false
}
