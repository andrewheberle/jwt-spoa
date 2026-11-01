package spoa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/verify"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/request"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	MessageName = "jwt-verify"
)

type Server struct {
	addr     string
	logger   *slog.Logger
	registry *prometheus.Registry

	ctx    context.Context
	cancel context.CancelFunc

	// jwt verification
	verifyOpts []verify.Option
	verifier   *verify.Verifier

	// metrics
	requestDuration *prometheus.HistogramVec
}

func NewServer(addr string, jwks string, issuer string, opts ...ServerOption) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		addr:     addr,
		logger:   slog.New(slog.DiscardHandler),
		registry: prometheus.NewRegistry(),
		ctx:      ctx,
		cancel:   cancel,
	}

	for _, o := range opts {
		o(s)
	}

	// set up jwt verifier
	s.verifier = verify.New(issuer, oidc.NewRemoteKeySet(ctx, jwks), append(s.verifyOpts, verify.WithLogger(s.logger))...)

	// set up metrics
	s.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "jwt_agent_request_duration_seconds",
			Help:    "Latency of request handling by the geoip lookup agent.",
			Buckets: []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25},
		},
		[]string{"status"},
	)

	// register metrics
	s.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		s.requestDuration,
	)

	return s, nil
}

func (s *Server) ListenAndServe() error {
	s.logger.Info("starting SPOA server", "listen", s.addr)
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.logger.Error("could not create listener", "error", err)
		return fmt.Errorf("could not create listener: %w", err)
	}

	a := agent.New(s.handler, s)

	errCh := make(chan error, 1)

	go func() {
		errCh <- a.Serve(l)
	}()

	select {
	case err := <-errCh:
		return err
	case <-s.ctx.Done():
		closeErr := l.Close()
		serveErr := <-errCh
		if closeErr != nil {
			return closeErr
		}
		if errors.Is(serveErr, net.ErrClosed) {
			return s.ctx.Err()
		}
		return serveErr
	}
}

func (s *Server) Shutdown() error {
	s.cancel()
	return nil
}

func (s *Server) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{
		Registry: s.registry,
	})
}

func (s *Server) handler(req *request.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		s.requestDuration.WithLabelValues(status).Observe(time.Since(start).Seconds())
	}()

	logger := s.logger.With("engineID", req.EngineID, "streamID", req.StreamID, "frameID", req.FrameID, "messages", req.Messages.Len())

	msg, err := req.Messages.GetByName(MessageName)
	if err != nil {
		status = "error"
		s.logger.Info("message was not found")
		return
	}

	jwtValue, ok := msg.KV.Get("jwt")
	if !ok {
		status = "error"
		logger.Warn("jwt was not found in message")
		return
	}

	signed, ok := jwtValue.(string)
	if !ok {
		status = "error"
		logger.Warn("jwt has incorrect type expected string")
		return
	}

	// ensure we always return jwt_valid as true/false from here onwards
	jwtValid := false
	defer func() {
		req.Actions.SetVar(action.ScopeTransaction, "jwt_valid", jwtValid)
	}()

	// verify JWT
	ctx, cancel := context.WithTimeout(s.ctx, time.Second*2)
	defer cancel()
	claims, err := s.verifier.Verify(ctx, signed)

	// set claim variables in claim order
	names := slices.Sorted(maps.Keys(claims))
	attrs := make([]slog.Attr, 0, len(names))
	for _, name := range names {
		attrs = append(attrs, slog.Any(name, claims[name]))
		req.Actions.SetVar(action.ScopeTransaction, fmt.Sprintf("claims.%s", name), claims[name])
	}

	if err != nil {
		status = "error"
		switch {
		case errors.Is(err, verify.ErrMissingRequiredClaim):
			logger.Error("a required claim was missing", "error", err)
		case errors.Is(err, verify.ErrInvalidClaims):
			logger.Error("could not parse JWT", "error", err)
		default:
			logger.Error("could not verify JWT", "error", err)
		}
		return
	}

	// mark JWT as valid
	jwtValid = true

	logger.Debug("handled request",
		"jwt_valid", jwtValid,
		slog.GroupAttrs("claims", attrs...),
	)
}

func (s *Server) Errorf(format string, args ...any) {
	s.logger.Error(fmt.Sprintf(format, args...))
}
