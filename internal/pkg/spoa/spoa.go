package spoa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/jwks"
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

	// jwksTimeout is how long a single JWKS fetch may take.
	jwksTimeout = time.Second * 10
)

// Config holds the settings for a Server.
type Config struct {
	// Listen is the address the SPOA listens on.
	Listen string
	// Issuer is the issuer (iss) the JWT must contain. Required.
	Issuer string
	// JWKS is the URL of the JSON Web Key Set used to verify JWT signatures.
	// Defaults to ISSUER/.well-known/jwks.json.
	JWKS string
	// JWKSMinRefresh is the minimum time between fetches of the JWKS. A key
	// set refresh within this time of the previous fetch is refused, and the
	// JWT is checked against the cached keys only. Must be greater than 0.
	JWKSMinRefresh time.Duration
	// Audience is the audience (aud) the JWT must contain. The audience is
	// not checked if empty.
	Audience string
	// Methods are the accepted signing methods. At least one is required.
	Methods []string
	// Claims are the claims to extract when present.
	Claims []string
	// RequiredClaims are the claims that must be present.
	RequiredClaims []string
	// MetricsListen is the address the Prometheus metrics listener listens
	// on. No metrics listener is started if empty.
	MetricsListen string
	// MetricsPath is the path metrics are served on. Defaults to /metrics.
	MetricsPath string
}

type Server struct {
	addr        string
	metricsAddr string
	metricsPath string
	jwks        string
	logger      *slog.Logger
	registry    *prometheus.Registry

	// jwt verification
	verifier *verify.Verifier

	// metrics
	requestDuration *prometheus.HistogramVec
	jwksFetches     *prometheus.CounterVec
	jwksSkipped     prometheus.Counter
}

// NewServer returns a Server for cfg. It returns an error if cfg is invalid.
func NewServer(cfg Config, opts ...ServerOption) (*Server, error) {
	jwksURL := cfg.JWKS
	if jwksURL == "" {
		u, err := url.JoinPath(cfg.Issuer, ".well-known/jwks.json")
		if err != nil {
			return nil, fmt.Errorf("creating JWKS URL from issuer: %w", err)
		}
		jwksURL = u
	}

	metricsPath := cfg.MetricsPath
	if metricsPath == "" {
		metricsPath = "/metrics"
	}

	s := &Server{
		addr:        cfg.Listen,
		metricsAddr: cfg.MetricsListen,
		metricsPath: metricsPath,
		jwks:        jwksURL,
		logger:      slog.New(slog.DiscardHandler),
		registry:    prometheus.NewRegistry(),
	}

	for _, o := range opts {
		o(s)
	}

	// set up metrics
	s.jwksFetches = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "jwt_agent_jwks_fetches_total",
			Help: "JWKS fetches sent to the JWKS URL, by result. A response that is not a valid key set still counts as a success.",
		},
		[]string{"result"},
	)
	s.jwksSkipped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "jwt_agent_jwks_fetches_skipped_total",
			Help: "Key set refreshes not sent to the JWKS URL because the previous fetch was too recent.",
		},
	)
	// export both results from the start
	s.jwksFetches.WithLabelValues("success")
	s.jwksFetches.WithLabelValues("error")

	// set up jwt verifier
	transport, err := jwks.NewTransport(cfg.JWKSMinRefresh,
		jwks.WithLogger(s.logger),
		jwks.WithMetrics(s.jwksFetches, s.jwksSkipped),
	)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS transport: %w", err)
	}
	v, err := newVerifier(cfg, newKeySet(jwksURL, transport), s.logger)
	if err != nil {
		return nil, err
	}
	s.verifier = v

	s.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "jwt_agent_request_duration_seconds",
			Help:    "Latency of request handling by the JWT verification agent.",
			Buckets: []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25},
		},
		[]string{"status"},
	)

	// register metrics
	s.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		s.requestDuration,
		s.jwksFetches,
		s.jwksSkipped,
	)

	return s, nil
}

// newKeySet returns a key set that fetches the JWKS from jwksURL with
// transport, which limits how often a key set refresh reaches the JWKS URL.
func newKeySet(jwksURL string, transport http.RoundTripper) oidc.KeySet {
	client := &http.Client{Transport: transport, Timeout: jwksTimeout}

	// the key set ignores cancellation of its context, which only carries
	// the client
	return oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), jwksURL)
}

// newVerifier returns the JWT verifier for cfg, checking signatures against keys.
func newVerifier(cfg Config, keys oidc.KeySet, logger *slog.Logger) (*verify.Verifier, error) {
	v, err := verify.New(cfg.Issuer, keys,
		verify.WithAudience(cfg.Audience),
		verify.WithValidMethods(cfg.Methods),
		verify.WithClaims(cfg.Claims),
		verify.WithRequiredClaims(cfg.RequiredClaims),
		verify.WithLogger(logger),
	)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	return v, nil
}

// Run serves the SPOA, and the metrics listener when configured, until ctx
// is cancelled or a listener fails. It returns nil once stopped by ctx, and
// an error if a listener could not be created or failed. A Server is run
// once.
func (s *Server) Run(ctx context.Context) error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("creating SPOA listener: %w", err)
	}

	var ml net.Listener
	if s.metricsAddr != "" {
		ml, err = net.Listen("tcp", s.metricsAddr)
		if err != nil {
			_ = l.Close()
			return fmt.Errorf("creating metrics listener: %w", err)
		}
	}

	return s.run(ctx, l, ml)
}

// run serves the SPOA on l, and metrics on ml when it is not nil, until ctx
// is cancelled or either stops. Both listeners are closed when run returns.
func (s *Server) run(ctx context.Context, l, ml net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, 2)
	running := 0

	s.logger.Info("starting SPOA server", "listen", l.Addr().String(), "jwks", s.jwks)
	a := agent.New(func(req *request.Request) { s.handler(ctx, req) }, s)
	running++
	go func() {
		// Serve only returns once the listener fails or is closed
		errs <- fmt.Errorf("serving SPOA: %w", a.Serve(l))
	}()

	var metrics *http.Server
	if ml != nil {
		mux := http.NewServeMux()
		mux.Handle(s.metricsPath, promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{
			Registry: s.registry,
		}))
		metrics = &http.Server{
			Handler:      mux,
			ReadTimeout:  time.Second * 2,
			WriteTimeout: time.Second * 2,
		}

		s.logger.Info("starting metrics listener", "listen", ml.Addr().String(), "path", s.metricsPath)
		running++
		go func() {
			// Serve only returns once the listener fails or the server is shut down
			errs <- fmt.Errorf("serving metrics: %w", metrics.Serve(ml))
		}()
	}

	// wait for cancellation or for a listener to stop
	var err error
	select {
	case <-ctx.Done():
		s.logger.Info("stopping")
	case err = <-errs:
		running--
	}

	// stop the SPOA listener; open connections are not drained
	_ = l.Close()

	if metrics != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second*2)
		defer shutdownCancel()

		if err := metrics.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("got error while shutting down metrics listener", "error", err)
		}
	}

	// wait for the remaining listeners, whose errors are from being stopped
	for ; running > 0; running-- {
		stopped := <-errs
		s.logger.Debug("listener stopped", "reason", stopped)
	}

	return err
}

func (s *Server) handler(ctx context.Context, req *request.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		s.requestDuration.WithLabelValues(status).Observe(time.Since(start).Seconds())
	}()

	logger := s.logger.With("engineID", req.EngineID, "streamID", req.StreamID, "frameID", req.FrameID, "messages", req.Messages.Len())

	// always return jwt_valid as true/false
	jwtValid := false
	defer func() {
		req.Actions.SetVar(action.ScopeTransaction, "jwt_valid", jwtValid)
	}()

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

	// verify JWT
	ctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	claims, err := s.verifier.Verify(ctx, signed)
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

	// set claim variables in claim order, only for a valid JWT
	names := slices.Sorted(maps.Keys(claims))
	attrs := make([]slog.Attr, 0, len(names))
	for _, name := range names {
		attrs = append(attrs, slog.Any(name, claims[name]))
		req.Actions.SetVar(action.ScopeTransaction, fmt.Sprintf("claims.%s", name), claims[name])
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
