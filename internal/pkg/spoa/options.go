package spoa

import (
	"log/slog"

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
		s.config.ClientID = aud
	}
}

func WithValidMethods(methods []string) ServerOption {
	return func(s *Server) {
		s.config.SupportedSigningAlgs = methods
	}
}

func WithClaims(claims []string) ServerOption {
	return func(s *Server) {
		s.claims = claims
	}
}
