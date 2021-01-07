package mtls

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type auth struct {
	cfg *TLSConfig
}

func (a *auth) authenticateStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	for _, item := range CertificatesFromContext(ss.Context()) {
		if isInAllowedCNs(item.Subject.CommonName, a.cfg.AllowedCNs) {
			handler(srv, ss)
			return nil
		}
	}

	return grpc.Errorf(codes.PermissionDenied, "Authentication failed.")
}

func (a *auth) authenticateRequest(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	for _, item := range CertificatesFromContext(ctx) {
		if isInAllowedCNs(item.Subject.CommonName, a.cfg.AllowedCNs) {
			return handler(ctx, req)
		}
	}

	return nil, grpc.Errorf(codes.PermissionDenied, "Authentication failed.")
}
