// Package jwks limits how often the JSON Web Key Set (JWKS) is fetched from
// the JWKS URL.
//
// A key set refresh happens whenever a JWT fails signature verification
// against the cached keys, in case the keys have rotated. Without a limit,
// anyone able to send JWTs with bad signatures could drive requests at the
// JWKS URL. Transport allows at most one fetch per interval and fails the
// rest without touching the network, leaving the cached keys in place.
package jwks

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrRefreshLimited is returned by Transport when a fetch is refused because
// the previous fetch started less than the interval ago.
var ErrRefreshLimited = errors.New("key set refresh limited")

// Transport is an http.RoundTripper that sends at most one request per
// interval to its base transport. The interval starts when a request starts,
// whether or not that request succeeds.
//
// It is meant for the http.Client used to fetch a single JWKS URL.
type Transport struct {
	base     http.RoundTripper
	interval time.Duration
	now      func() time.Time
	logger   *slog.Logger
	fetches  *prometheus.CounterVec
	skipped  prometheus.Counter

	mu      sync.Mutex
	fetched bool
	last    time.Time
}

// Option configures a Transport.
type Option func(*Transport)

// WithBase sets the transport that allowed requests are sent with. The
// default is http.DefaultTransport.
func WithBase(base http.RoundTripper) Option {
	return func(t *Transport) {
		t.base = base
	}
}

// WithLogger sets the logger used to report fetches. Failed fetches are
// logged as warnings and successful ones at debug level. Refused fetches are
// not logged, as their rate is set by whoever is sending JWTs. By default
// nothing is logged.
func WithLogger(logger *slog.Logger) Option {
	return func(t *Transport) {
		t.logger = logger
	}
}

// WithMetrics sets the counters for fetches sent, labelled by a "result" of
// "success" or "error", and for fetches refused by the limit. By default
// nothing is counted.
func WithMetrics(fetches *prometheus.CounterVec, skipped prometheus.Counter) Option {
	return func(t *Transport) {
		t.fetches = fetches
		t.skipped = skipped
	}
}

// WithClock sets the function used to get the current time. The default is
// time.Now.
func WithClock(now func() time.Time) Option {
	return func(t *Transport) {
		t.now = now
	}
}

// NewTransport returns a Transport that allows one request per interval,
// which must be greater than 0.
func NewTransport(interval time.Duration, opts ...Option) (*Transport, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("minimum time between JWKS fetches must be greater than 0, got %s", interval)
	}

	t := &Transport{
		base:     http.DefaultTransport,
		interval: interval,
		now:      time.Now,
		logger:   slog.New(slog.DiscardHandler),
	}

	for _, o := range opts {
		o(t)
	}

	return t, nil
}

// RoundTrip sends req with the base transport if the previous request
// started at least the interval ago, and otherwise returns an error wrapping
// ErrRefreshLimited.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.allow() {
		if t.skipped != nil {
			t.skipped.Inc()
		}
		return nil, fmt.Errorf("fetching %s: %w", req.URL.Redacted(), ErrRefreshLimited)
	}

	resp, err := t.base.RoundTrip(req)

	logger := t.logger.With("url", req.URL.Redacted())
	switch {
	case err != nil:
		t.count("error")
		logger.Warn("could not fetch JWKS", "error", err)
	case resp.StatusCode != http.StatusOK:
		t.count("error")
		logger.Warn("could not fetch JWKS", "status", resp.StatusCode)
	default:
		t.count("success")
		logger.Debug("fetched JWKS")
	}

	return resp, err
}

// allow reports whether a request may be sent now, and if so starts a new
// interval.
func (t *Transport) allow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	if t.fetched && now.Sub(t.last) < t.interval {
		return false
	}

	t.fetched = true
	t.last = now

	return true
}

func (t *Transport) count(result string) {
	if t.fetches != nil {
		t.fetches.WithLabelValues(result).Inc()
	}
}
