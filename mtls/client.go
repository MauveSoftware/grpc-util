package mtls

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DialOptions returns the dial options needed to fulfil the transport encryption requirements defined in the TLS config
func DialOptions(cfg *TLSConfig) ([]grpc.DialOption, error) {
	if !cfg.Enabled {
		return []grpc.DialOption{
			grpc.WithInsecure(),
		}, nil
	}

	tls, err := loadTLSCert(cfg)
	if err != nil {
		return nil, err
	}

	return []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tls)),
	}, nil
}
