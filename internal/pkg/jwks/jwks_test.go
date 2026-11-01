package jwks

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// fakeBase is an http.RoundTripper that counts requests and answers each with
// status, or fails with err when it is set.
type fakeBase struct {
	mu       sync.Mutex
	requests int
	status   int
	err      error
}

func (f *fakeBase) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests++
	if f.err != nil {
		return nil, f.err
	}

	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
		Request:    req,
	}, nil
}

// fakeClock is a clock that only moves when advanced.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestNewTransport(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		wantErr  bool
	}{
		{name: "positive interval", interval: time.Minute},
		{name: "zero interval is an error", interval: 0, wantErr: true},
		{name: "negative interval is an error", interval: -time.Second, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTransport(tt.interval)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewTransport() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTransport_RoundTrip(t *testing.T) {
	const interval = time.Minute

	// step is one request, sent after advancing the clock by advance
	type step struct {
		advance time.Duration
		wantErr error
	}

	tests := []struct {
		name         string
		status       int
		baseErr      error
		steps        []step
		wantRequests int
		wantSuccess  float64
		wantError    float64
		wantSkipped  float64
	}{
		{
			name:         "first request is sent",
			status:       http.StatusOK,
			steps:        []step{{}},
			wantRequests: 1,
			wantSuccess:  1,
		},
		{
			name:         "requests within the interval are refused",
			status:       http.StatusOK,
			steps:        []step{{}, {wantErr: ErrRefreshLimited}, {advance: interval - time.Nanosecond, wantErr: ErrRefreshLimited}},
			wantRequests: 1,
			wantSuccess:  1,
			wantSkipped:  2,
		},
		{
			name:         "request once the interval has passed is sent",
			status:       http.StatusOK,
			steps:        []step{{}, {advance: interval}},
			wantRequests: 2,
			wantSuccess:  2,
		},
		{
			name:         "interval runs from the last request sent, not the last refused",
			status:       http.StatusOK,
			steps:        []step{{}, {advance: interval / 2, wantErr: ErrRefreshLimited}, {advance: interval / 2}},
			wantRequests: 2,
			wantSuccess:  2,
			wantSkipped:  1,
		},
		{
			name:         "non-200 response counts as an error and against the interval",
			status:       http.StatusInternalServerError,
			steps:        []step{{}, {wantErr: ErrRefreshLimited}},
			wantRequests: 1,
			wantError:    1,
			wantSkipped:  1,
		},
		{
			name:         "transport error counts as an error and against the interval",
			baseErr:      errors.New("connection refused"),
			steps:        []step{{wantErr: errBase}, {wantErr: ErrRefreshLimited}},
			wantRequests: 1,
			wantError:    1,
			wantSkipped:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &fakeBase{status: tt.status, err: tt.baseErr}
			clock := &fakeClock{now: time.Unix(0, 0)}
			fetches := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "fetches"}, []string{"result"})
			skipped := prometheus.NewCounter(prometheus.CounterOpts{Name: "skipped"})
			reg := prometheus.NewRegistry()
			reg.MustRegister(fetches, skipped)

			tr, err := NewTransport(interval, WithBase(base), WithClock(clock.Now), WithMetrics(fetches, skipped))
			if err != nil {
				t.Fatalf("NewTransport() error = %v", err)
			}

			for i, s := range tt.steps {
				clock.Advance(s.advance)

				req, err := http.NewRequest(http.MethodGet, "https://issuer.example.com/jwks.json", nil)
				if err != nil {
					t.Fatalf("NewRequest() error = %v", err)
				}

				resp, err := tr.RoundTrip(req)
				if resp != nil {
					_ = resp.Body.Close()
				}

				switch {
				case s.wantErr == nil && err != nil:
					t.Errorf("request %d: RoundTrip() error = %v, want nil", i, err)
				case s.wantErr == errBase && (err == nil || errors.Is(err, ErrRefreshLimited)):
					t.Errorf("request %d: RoundTrip() error = %v, want the base transport's error", i, err)
				case s.wantErr != nil && s.wantErr != errBase && !errors.Is(err, s.wantErr):
					t.Errorf("request %d: RoundTrip() error = %v, want %v", i, err, s.wantErr)
				}
			}

			if base.requests != tt.wantRequests {
				t.Errorf("requests sent = %d, want %d", base.requests, tt.wantRequests)
			}
			if got := counterValue(t, reg, "fetches", "success"); got != tt.wantSuccess {
				t.Errorf("success fetches = %v, want %v", got, tt.wantSuccess)
			}
			if got := counterValue(t, reg, "fetches", "error"); got != tt.wantError {
				t.Errorf("error fetches = %v, want %v", got, tt.wantError)
			}
			if got := counterValue(t, reg, "skipped", ""); got != tt.wantSkipped {
				t.Errorf("skipped fetches = %v, want %v", got, tt.wantSkipped)
			}
		})
	}
}

// counterValue returns the value of the counter called name in reg, with a
// "result" label of result when it is not empty, or 0 if it has no value.
func counterValue(t *testing.T, reg *prometheus.Registry, name, result string) float64 {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if result == "" {
				return m.GetCounter().GetValue()
			}
			for _, l := range m.GetLabel() {
				if l.GetName() == "result" && l.GetValue() == result {
					return m.GetCounter().GetValue()
				}
			}
		}
	}

	return 0
}

// errBase marks a step that expects the base transport's own error.
var errBase = errors.New("base transport error")

func TestTransport_RoundTrip_concurrent(t *testing.T) {
	base := &fakeBase{status: http.StatusOK}
	tr, err := NewTransport(time.Hour, WithBase(base))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			req, _ := http.NewRequest(http.MethodGet, "https://issuer.example.com/jwks.json", nil)
			if resp, err := tr.RoundTrip(req); err == nil {
				_ = resp.Body.Close()
			}
		})
	}
	wg.Wait()

	if base.requests != 1 {
		t.Errorf("requests sent = %d, want 1", base.requests)
	}
}
