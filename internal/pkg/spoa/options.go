package spoa

import (
	"log/slog"
	"slices"

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
		// append to claims and ensure list is sorted and with no dupes
		s.claims = append(s.claims, claims...)
		slices.Sort(s.claims)
		s.claims = slices.Compact(s.claims)
	}
}

func WithRequiredClaims(claims []string) ServerOption {
	return func(s *Server) {
		// append to requiredClaims and ensure list is sorted and with no dupes
		s.requiredClaims = append(s.requiredClaims, claims...)
		slices.Sort(s.requiredClaims)
		s.requiredClaims = slices.Compact(s.requiredClaims)
		// also append to claims and ensure list is sorted and with no dupes
		s.claims = append(s.claims, claims...)
		slices.Sort(s.claims)
		s.claims = slices.Compact(s.claims)
	}
}
