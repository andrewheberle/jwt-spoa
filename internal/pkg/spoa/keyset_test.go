package spoa

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/jwks"
	"github.com/andrewheberle/jwt-spoa/internal/pkg/verify/verifytest"
)

// fakeJWKS is an http.RoundTripper that serves the JWKS of the current signer
// and counts the requests it gets.
type fakeJWKS struct {
	t        testing.TB
	mu       sync.Mutex
	signer   *verifytest.Signer
	requests int
}

func (f *fakeJWKS) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests++

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(f.signer.JWKS(f.t))),
		Request:    req,
	}, nil
}

func (f *fakeJWKS) rotate(signer *verifytest.Signer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signer = signer
}

func (f *fakeJWKS) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
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

// TestKeySetRefreshLimit checks that JWTs failing signature verification
// cannot make the key set be fetched more than once per interval, while a
// rotated key is still picked up once the interval has passed.
func TestKeySetRefreshLimit(t *testing.T) {
	const interval = time.Minute

	current := verifytest.NewSigner(t)
	attacker := verifytest.NewSigner(t)
	rotated := verifytest.NewSigner(t)

	claims := map[string]any{
		"iss": testIssuer,
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	server := &fakeJWKS{t: t, signer: current}
	clock := &fakeClock{now: time.Unix(0, 0)}

	transport, err := jwks.NewTransport(interval, jwks.WithBase(server), jwks.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}

	cfg := Config{Issuer: testIssuer, Audience: testAudience, Methods: []string{"RS256"}}
	v, err := newVerifier(cfg, newKeySet("https://issuer.example.com/jwks.json", transport), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newVerifier() error = %v", err)
	}

	// each step sends count JWTs signed by signer, after advancing the clock
	steps := []struct {
		name         string
		advance      time.Duration
		rotate       *verifytest.Signer
		signer       *verifytest.Signer
		count        int
		wantValid    bool
		wantRequests int
	}{
		{
			name:         "first JWT fetches the key set",
			signer:       current,
			count:        1,
			wantValid:    true,
			wantRequests: 1,
		},
		{
			name:         "invalid signatures do not fetch the key set again",
			signer:       attacker,
			count:        100,
			wantRequests: 1,
		},
		{
			name:         "valid JWTs are checked against the cached keys",
			signer:       current,
			count:        10,
			wantValid:    true,
			wantRequests: 1,
		},
		{
			name:         "JWT signed by a rotated key fails within the interval",
			rotate:       rotated,
			signer:       rotated,
			count:        1,
			wantRequests: 1,
		},
		{
			name:         "JWT signed by a rotated key passes once the interval has passed",
			advance:      interval,
			signer:       rotated,
			count:        1,
			wantValid:    true,
			wantRequests: 2,
		},
		{
			name:         "invalid signatures after the rotation do not fetch the key set again",
			signer:       attacker,
			count:        100,
			wantRequests: 2,
		},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			clock.Advance(step.advance)
			if step.rotate != nil {
				server.rotate(step.rotate)
			}

			jwt := step.signer.Sign(t, claims)
			for i := range step.count {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
				_, err := v.Verify(ctx, jwt)
				cancel()

				if valid := err == nil; valid != step.wantValid {
					t.Fatalf("JWT %d: Verify() error = %v, want valid %v", i, err, step.wantValid)
				}
			}

			if got := server.count(); got != step.wantRequests {
				t.Errorf("JWKS requests = %d, want %d", got, step.wantRequests)
			}
		})
	}
}
