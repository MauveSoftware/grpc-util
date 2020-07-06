package mtls

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// NewGRPCServer creates a new GRPC server with TLS configured
func NewGRPCServer(cfg *TLSConfig, opt ...grpc.ServerOption) (*grpc.Server, error) {
	if !cfg.Enabled {
		return grpc.NewServer(opt...), nil
	}

	tlsConfig, err := LoadTLSCert(cfg)
	if err != nil {
		return nil, err
	}

	creds := grpc.Creds(credentials.NewTLS(tlsConfig))
	opt = append(opt, creds)

	auth := &auth{
		cfg: cfg,
	}
	opt = append(opt, grpc.ChainUnaryInterceptor(auth.filterAllowedCNs))

	return grpc.NewServer(opt...), nil
}
