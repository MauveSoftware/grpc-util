package mtls

import (
	"context"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type auth struct {
	cfg *TLSConfig
}

func (a *auth) filterAllowedCNs(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	if p, ok := peer.FromContext(ctx); ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			for _, item := range mtls.State.PeerCertificates {
				if isInAllowedCNs(item.Subject.CommonName, a.cfg.AllowedCNs) {
					return handler(ctx, req)
				}
			}
		}
	}

	return nil, errors.Errorf("CN of client is not in list of allowed CNs")
}
