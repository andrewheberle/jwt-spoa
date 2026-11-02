package verifycache

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var errInvalid = errors.New("invalid token")

// fakeVerifier passes every JWT except those in fail, returning the JWT as
// the "sub" claim value, and counts its calls.
type fakeVerifier struct {
	fail map[string]bool

	mu    sync.Mutex
	calls int
}

func (f *fakeVerifier) Verify(_ context.Context, signed string) (map[string]any, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()

	if f.fail[signed] {
		return nil, errInvalid
	}

	return map[string]any{"sub": signed}, nil
}

// value returns the current value of a counter or gauge.
func value(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()

	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatalf("reading metric: %v", err)
	}
	if out.Counter != nil {
		return out.Counter.GetValue()
	}

	return out.Gauge.GetValue()
}

// token returns an unsigned compact JWT carrying claims.
func token(t *testing.T, claims map[string]any) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encoding claims: %v", err)
	}

	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestCache_VerifyCached(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)

	// tokens expiring an hour and a minute after start
	hour := token(t, map[string]any{"sub": "a", "exp": start.Add(time.Hour).Unix()})
	other := token(t, map[string]any{"sub": "b", "exp": start.Add(time.Hour).Unix()})
	third := token(t, map[string]any{"sub": "c", "exp": start.Add(time.Hour).Unix()})
	minute := token(t, map[string]any{"sub": "d", "exp": start.Add(time.Minute).Unix()})
	noExp := token(t, map[string]any{"sub": "e"})

	type lookup struct {
		advance    time.Duration
		jwt        string
		wantCached bool
		wantErr    error
	}
	tests := []struct {
		name         string
		maxEntries   int
		maxAge       time.Duration
		fail         []string
		lookups      []lookup
		wantCalls    int
		wantHits     float64
		wantMisses   float64
		wantCapacity float64
		wantExpired  float64
		wantEntries  float64
	}{
		{
			name:       "repeat JWT is a hit",
			maxEntries: 10,
			maxAge:     5 * time.Minute,
			lookups: []lookup{
				{jwt: hour},
				{jwt: hour, wantCached: true},
				{jwt: hour, wantCached: true},
			},
			wantCalls:   1,
			wantHits:    2,
			wantMisses:  1,
			wantEntries: 1,
		},
		{
			name:       "JWT that fails is not cached",
			maxEntries: 10,
			maxAge:     5 * time.Minute,
			fail:       []string{hour},
			lookups: []lookup{
				{jwt: hour, wantErr: errInvalid},
				{jwt: hour, wantErr: errInvalid},
			},
			wantCalls:  2,
			wantMisses: 2,
		},
		{
			name:       "entry expires at the JWT's exp",
			maxEntries: 10,
			maxAge:     5 * time.Minute,
			lookups: []lookup{
				{jwt: minute},
				{advance: 59 * time.Second, jwt: minute, wantCached: true},
				{advance: time.Second, jwt: minute},
			},
			wantCalls:   2,
			wantHits:    1,
			wantMisses:  2,
			wantExpired: 1,
		},
		{
			name:       "entry expires at the maximum age",
			maxEntries: 10,
			maxAge:     5 * time.Minute,
			lookups: []lookup{
				{jwt: hour},
				{advance: 5*time.Minute - time.Second, jwt: hour, wantCached: true},
				{advance: time.Second, jwt: hour},
			},
			wantCalls:   2,
			wantHits:    1,
			wantMisses:  2,
			wantExpired: 1,
			wantEntries: 1,
		},
		{
			name:       "least recently used entry is evicted when full",
			maxEntries: 2,
			maxAge:     5 * time.Minute,
			lookups: []lookup{
				{jwt: hour},
				{jwt: other},
				{jwt: hour, wantCached: true},
				{jwt: third},
				{jwt: hour, wantCached: true},
				{jwt: other},
			},
			wantCalls:    4,
			wantHits:     2,
			wantMisses:   4,
			wantCapacity: 2,
			wantEntries:  2,
		},
		{
			name:       "JWT without exp is not cached",
			maxEntries: 10,
			maxAge:     5 * time.Minute,
			lookups: []lookup{
				{jwt: noExp},
				{jwt: noExp},
			},
			wantCalls:  2,
			wantMisses: 2,
		},
		{
			name:       "malformed JWT that passes is not cached",
			maxEntries: 10,
			maxAge:     5 * time.Minute,
			lookups: []lookup{
				{jwt: "not-a-jwt"},
				{jwt: "not-a-jwt"},
			},
			wantCalls:  2,
			wantMisses: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := start
			next := &fakeVerifier{fail: map[string]bool{}}
			for _, jwt := range tt.fail {
				next.fail[jwt] = true
			}
			lookups := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "lookups"}, []string{"result"})
			evictions := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "evictions"}, []string{"reason"})
			size := prometheus.NewGauge(prometheus.GaugeOpts{Name: "entries"})

			c, err := New(next, tt.maxEntries, tt.maxAge,
				WithClock(func() time.Time { return now }),
				WithMetrics(lookups, evictions, size),
			)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			for i, l := range tt.lookups {
				now = now.Add(l.advance)

				claims, cached, err := c.VerifyCached(context.Background(), l.jwt)
				if !errors.Is(err, l.wantErr) {
					t.Fatalf("lookup %d: VerifyCached() error = %v, want %v", i, err, l.wantErr)
				}
				if cached != l.wantCached {
					t.Errorf("lookup %d: VerifyCached() cached = %v, want %v", i, cached, l.wantCached)
				}
				if l.wantErr == nil && !reflect.DeepEqual(claims, map[string]any{"sub": l.jwt}) {
					t.Errorf("lookup %d: VerifyCached() claims = %#v", i, claims)
				}
			}

			if next.calls != tt.wantCalls {
				t.Errorf("verifier calls = %d, want %d", next.calls, tt.wantCalls)
			}
			for _, m := range []struct {
				name string
				got  float64
				want float64
			}{
				{"hits", value(t, lookups.WithLabelValues("hit")), tt.wantHits},
				{"misses", value(t, lookups.WithLabelValues("miss")), tt.wantMisses},
				{"capacity evictions", value(t, evictions.WithLabelValues("capacity")), tt.wantCapacity},
				{"expired evictions", value(t, evictions.WithLabelValues("expired")), tt.wantExpired},
				{"entries", value(t, size), tt.wantEntries},
			} {
				if m.got != m.want {
					t.Errorf("%s = %v, want %v", m.name, m.got, m.want)
				}
			}
		})
	}
}

func TestCache_Verify_returnsCopy(t *testing.T) {
	jwt := token(t, map[string]any{"sub": "a", "exp": time.Now().Add(time.Hour).Unix()})

	c, err := New(&fakeVerifier{}, 10, time.Minute)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// changing the claims returned by a miss or a hit must not change the entry
	for i := range 3 {
		claims, err := c.Verify(context.Background(), jwt)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if want := map[string]any{"sub": jwt}; !reflect.DeepEqual(claims, want) {
			t.Fatalf("Verify() call %d claims = %#v, want %#v", i, claims, want)
		}
		claims["sub"] = "changed"
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name       string
		maxEntries int
		maxAge     time.Duration
		wantErr    bool
	}{
		{name: "valid", maxEntries: 1, maxAge: time.Second},
		{name: "zero entries", maxEntries: 0, maxAge: time.Second, wantErr: true},
		{name: "negative entries", maxEntries: -1, maxAge: time.Second, wantErr: true},
		{name: "zero age", maxEntries: 1, maxAge: 0, wantErr: true},
		{name: "negative age", maxEntries: 1, maxAge: -time.Second, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(&fakeVerifier{}, tt.maxEntries, tt.maxAge); (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_expiry(t *testing.T) {
	tests := []struct {
		name   string
		jwt    string
		want   time.Time
		wantOK bool
	}{
		{name: "integer exp", jwt: "e30.eyJleHAiOjE4MDAwMDAwMDB9.sig", want: time.Unix(1_800_000_000, 0), wantOK: true},
		{name: "fractional exp", jwt: "e30.eyJleHAiOjE4MDAwMDAwMDAuNX0.sig", want: time.Unix(1_800_000_000, 500_000_000), wantOK: true},
		{name: "no exp", jwt: "e30.e30.sig"},
		{name: "exp not a number", jwt: "e30.eyJleHAiOiJzb29uIn0.sig"},
		{name: "payload not base64", jwt: "e30.!!!.sig"},
		{name: "payload not JSON", jwt: "e30.bm90LWpzb24.sig"},
		{name: "too few parts", jwt: "e30.e30"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := expiry(tt.jwt)
			if ok != tt.wantOK {
				t.Fatalf("expiry() ok = %v, want %v", ok, tt.wantOK)
			}
			if !got.Equal(tt.want) {
				t.Errorf("expiry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkCache_Verify_miss(b *testing.B) {
	// distinct JWTs, so every lookup misses and adds an entry
	exp := time.Now().Add(time.Hour).Unix()
	jwts := make([]string, 4096)
	for i := range jwts {
		payload, _ := json.Marshal(map[string]any{"sub": i, "exp": exp})
		jwts[i] = "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	}

	c, err := New(&fakeVerifier{}, len(jwts)/2, time.Hour)
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	i := 0
	for b.Loop() {
		_, _ = c.Verify(ctx, jwts[i%len(jwts)])
		i++
	}
}
