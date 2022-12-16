package mtls

import (
	"crypto/x509"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Listener handles authenticated certificates
type Listener func(*x509.Certificate)

// ServerOptions returns the server options needed to fulfil the transport encryption requirements defined in the TLS config
func ServerOptions(cfg *TLSConfig, listeners ...Listener) ([]grpc.ServerOption, error) {
	opt := []grpc.ServerOption{}

	if !cfg.Enabled {
		return opt, nil
	}

	tlsConfig, err := loadTLSCert(cfg)
	if err != nil {
		return nil, err
	}

	creds := grpc.Creds(credentials.NewTLS(tlsConfig))
	opt = append(opt, creds)

	auth := &authenticator{
		cfg:       cfg,
		listeners: listeners,
	}
	opt = append(opt, grpc.ChainStreamInterceptor(auth.authenticateStream), grpc.ChainUnaryInterceptor(auth.authenticateRequest))

	return opt, nil
}
