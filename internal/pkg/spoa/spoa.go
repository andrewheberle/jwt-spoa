package spoa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"

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
	addr           string
	logger         *slog.Logger
	registry       *prometheus.Registry
	claims         []string
	requiredClaims []string

	ctx    context.Context
	cancel context.CancelFunc

	// jwt verification
	config   *oidc.Config
	keyset   *oidc.RemoteKeySet
	verifier *oidc.IDTokenVerifier

	// metrics
	requestDuration *prometheus.HistogramVec
}

func NewServer(addr string, jwks string, issuer string, opts ...ServerOption) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		addr:           addr,
		logger:         slog.New(slog.DiscardHandler),
		registry:       prometheus.NewRegistry(),
		claims:         make([]string, 0),
		requiredClaims: make([]string, 0),
		ctx:            ctx,
		cancel:         cancel,
		keyset:         oidc.NewRemoteKeySet(ctx, jwks),
		config:         &oidc.Config{},
	}

	for _, o := range opts {
		o(s)
	}

	// set up jwt verifier
	s.verifier = oidc.NewVerifier(issuer, s.keyset, s.config)

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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	parsed, err := s.verifier.Verify(ctx, signed)
	if err != nil {
		status = "error"
		logger.Error("could not verify JWT", "error", err)
		return
	}

	// extract wanted claims and set variables
	var all map[string]json.RawMessage
	if err := parsed.Claims(&all); err != nil {
		status = "error"
		logger.Error("could not parse JWT", "error", err)
		return
	}
	attrs := make([]slog.Attr, 0)
	for _, claim := range s.claims {
		if v, ok := all[claim]; ok {
			value, err := toValue(v)
			if err != nil {
				logger.Warn("problem converting claim value to a supported type", "claim", claim, "error", err)
				continue
			}
			attrs = append(attrs, slog.Any(claim, value))
			req.Actions.SetVar(action.ScopeTransaction, fmt.Sprintf("claims.%s", claim), value)
		} else {
			// check if missing claim was required
			if slices.Contains(s.requiredClaims, claim) {
				logger.Error("a required claim was missing", "claim", claim)
				return
			}
			logger.Warn("an expected claim was missing", "claim", claim)
		}
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

func toValue(raw json.RawMessage) (any, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}

	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		return t, nil
	case float64:
		// JSON numbers decode as float64; convert to int if it's whole.
		if t == float64(int64(t)) {
			return int(t), nil
		}
		// non-whole number — Foo can't take a float, so decide:
		// here we fall back to a string representation.
		return fmt.Sprintf("%v", t), nil
	case nil:
		return "", nil // or however you want to represent null
	default:
		// array or object - re-marshal to a compact JSON string
		b, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	}
}
