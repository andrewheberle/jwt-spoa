package spoa

import (
	"log/slog"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/verify"
	"github.com/prometheus/client_golang/prometheus"
)

type ServerOption func(*Server)

func WithLogger(logger *slog.Logger) ServerOption {
	return func(s *Server) {
		s.logger = logger
	}
}

func WithRegistry(registry *prometheus.Registry) ServerOption {
	return func(s *Server) {
		s.registry = registry
	}
}

func WithAudience(aud string) ServerOption {
	return func(s *Server) {
		s.verifyOpts = append(s.verifyOpts, verify.WithAudience(aud))
	}
}

func WithValidMethods(methods []string) ServerOption {
	return func(s *Server) {
		s.verifyOpts = append(s.verifyOpts, verify.WithValidMethods(methods))
	}
}

func WithClaims(claims []string) ServerOption {
	return func(s *Server) {
		s.verifyOpts = append(s.verifyOpts, verify.WithClaims(claims))
	}
}

func WithRequiredClaims(claims []string) ServerOption {
	return func(s *Server) {
		s.verifyOpts = append(s.verifyOpts, verify.WithRequiredClaims(claims))
	}
}
