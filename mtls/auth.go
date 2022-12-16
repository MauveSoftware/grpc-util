package mtls

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authenticator struct {
	cfg       *TLSConfig
	listeners []Listener
}

func (a *authenticator) authenticateStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	for _, item := range CertificatesFromContext(ss.Context()) {
		if isInAllowedCNs(item.Subject.CommonName, a.cfg.AllowedCNs) {
			for _, l := range a.listeners {
				l(item)
			}
			handler(srv, ss)
			return nil
		}
	}

	return status.Errorf(codes.PermissionDenied, "Authentication failed.")
}

func (a *authenticator) authenticateRequest(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	for _, item := range CertificatesFromContext(ctx) {
		if isInAllowedCNs(item.Subject.CommonName, a.cfg.AllowedCNs) {
			for _, l := range a.listeners {
				l(item)
			}
			return handler(ctx, req)
		}
	}

	return nil, status.Errorf(codes.PermissionDenied, "Authentication failed.")
}
