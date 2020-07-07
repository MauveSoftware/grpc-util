package mtls

import (
	"context"
	"crypto/x509"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type auth struct {
	cfg *TLSConfig
}

func (a *auth) authenticateStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	for _, item := range a.certificatesFromContext(ss.Context()) {
		if isInAllowedCNs(item.Subject.CommonName, a.cfg.AllowedCNs) {
			handler(srv, ss)
			return nil
		}
	}

	return grpc.Errorf(codes.PermissionDenied, "Authentication failed.")
}

func (a *auth) authenticateRequest(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	for _, item := range a.certificatesFromContext(ctx) {
		if isInAllowedCNs(item.Subject.CommonName, a.cfg.AllowedCNs) {
			return handler(ctx, req)
		}
	}

	return nil, grpc.Errorf(codes.PermissionDenied, "Authentication failed.")
}

func (a *auth) certificatesFromContext(ctx context.Context) []*x509.Certificate {
	if p, ok := peer.FromContext(ctx); ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			return mtls.State.PeerCertificates
		}
	}

	return []*x509.Certificate{}
}
