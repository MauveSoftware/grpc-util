package mtls

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ServerOptions returns the server options needed to fulfil the transport encryption requirements defined in the TLS config
func ServerOptions(cfg *TLSConfig) ([]grpc.ServerOption, error) {
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

	auth := &auth{
		cfg: cfg,
	}
	opt = append(opt, grpc.ChainStreamInterceptor(auth.authenticateStream))
	opt = append(opt, grpc.ChainUnaryInterceptor(auth.authenticateRequest))

	return opt, nil
}
