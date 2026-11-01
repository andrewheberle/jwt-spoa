package spoa

import (
	"context"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/verify/verifytest"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/message"
	"github.com/negasus/haproxy-spoe-go/payload/kv"
	"github.com/negasus/haproxy-spoe-go/request"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "jwt-spoa"
)

// newTestServer returns a Server for cfg whose verifier checks JWTs against
// signer rather than a remote JWKS. Listen, Issuer, JWKS and Methods are
// filled in.
func newTestServer(t testing.TB, signer *verifytest.Signer, cfg Config) *Server {
	t.Helper()

	cfg.Listen = "127.0.0.1:0"
	cfg.Issuer = testIssuer
	cfg.JWKS = "http://127.0.0.1:0/jwks.json"
	cfg.Methods = []string{"RS256"}

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	v, err := newVerifier(cfg, signer.KeySet(), s.logger)
	if err != nil {
		t.Fatalf("newVerifier() error = %v", err)
	}
	s.verifier = v

	return s
}

// newRequest returns an SPOE request carrying one message with the given
// name and key/values.
func newRequest(name string, values map[string]any) *request.Request {
	req := request.AcquireRequest()

	msg := &message.Message{Name: name, KV: kv.NewKV()}
	for k, v := range values {
		msg.KV.Add(k, v)
	}
	*req.Messages = append(*req.Messages, msg)

	return req
}

func setVar(name string, value any) action.Action {
	return action.NewSetVar(action.ScopeTransaction, name, value)
}

func TestServer_handler(t *testing.T) {
	signer := verifytest.NewSigner(t)
	other := verifytest.NewSigner(t)

	claims := func(extra map[string]any) map[string]any {
		c := map[string]any{
			"iss": testIssuer,
			"aud": testAudience,
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}

	tests := []struct {
		name    string
		cfg     Config
		message string
		values  map[string]any
		want    action.Actions
	}{
		{
			name: "valid JWT sets claims then jwt_valid true",
			cfg: Config{
				Audience: testAudience,
				Claims:   []string{"email", "admin"},
			},
			message: MessageName,
			values: map[string]any{
				"jwt": signer.Sign(t, claims(map[string]any{"email": "user@example.com", "admin": true})),
			},
			want: action.Actions{
				setVar("claims.admin", true),
				setVar("claims.email", "user@example.com"),
				setVar("jwt_valid", true),
			},
		},
		{
			name:    "JWT signed by another key sets jwt_valid false",
			cfg:     Config{Audience: testAudience},
			message: MessageName,
			values:  map[string]any{"jwt": other.Sign(t, claims(nil))},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
		{
			name: "missing required claim sets no claims and jwt_valid false",
			cfg: Config{
				Audience:       testAudience,
				Claims:         []string{"a_claim"},
				RequiredClaims: []string{"email"},
			},
			message: MessageName,
			values:  map[string]any{"jwt": signer.Sign(t, claims(map[string]any{"a_claim": "a"}))},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
		{
			name:    "missing jwt-verify message sets jwt_valid false",
			cfg:     Config{Audience: testAudience},
			message: "something-else",
			values:  map[string]any{"jwt": signer.Sign(t, claims(nil))},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
		{
			name:    "missing jwt key sets jwt_valid false",
			cfg:     Config{Audience: testAudience},
			message: MessageName,
			values:  map[string]any{"token": signer.Sign(t, claims(nil))},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
		{
			name:    "jwt of wrong type sets jwt_valid false",
			cfg:     Config{Audience: testAudience},
			message: MessageName,
			values:  map[string]any{"jwt": 42},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, signer, tt.cfg)
			req := newRequest(tt.message, tt.values)
			defer request.ReleaseRequest(req)

			s.handler(context.Background(), req)

			if !reflect.DeepEqual(req.Actions, tt.want) {
				t.Errorf("handler() actions = %#v, want %#v", req.Actions, tt.want)
			}
		})
	}
}

func TestServer_metricsHelp(t *testing.T) {
	s := newTestServer(t, verifytest.NewSigner(t), Config{})

	// observe once so the histogram is gathered
	s.requestDuration.WithLabelValues("success").Observe(0)

	families, err := s.registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	tests := []struct {
		name string
		help string
	}{
		{
			name: "jwt_agent_request_duration_seconds",
			help: "Latency of request handling by the JWT verification agent.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, f := range families {
				if f.GetName() == tt.name {
					if f.GetHelp() != tt.help {
						t.Errorf("help = %q, want %q", f.GetHelp(), tt.help)
					}
					return
				}
			}
			t.Fatalf("metric %s not registered", tt.name)
		})
	}
}

func TestNewServer(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		wantJWKS string
		wantErr  bool
	}{
		{
			name: "explicit JWKS is used",
			cfg: Config{
				Issuer:  testIssuer,
				JWKS:    "https://keys.example.com/jwks.json",
				Methods: []string{"RS256"},
			},
			wantJWKS: "https://keys.example.com/jwks.json",
		},
		{
			name:     "empty JWKS defaults from issuer",
			cfg:      Config{Issuer: testIssuer, Methods: []string{"RS256"}},
			wantJWKS: testIssuer + "/.well-known/jwks.json",
		},
		{
			name:     "issuer with trailing slash gives a clean JWKS URL",
			cfg:      Config{Issuer: testIssuer + "/", Methods: []string{"RS256"}},
			wantJWKS: testIssuer + "/.well-known/jwks.json",
		},
		{
			name:    "issuer that is not a URL is an error when JWKS is empty",
			cfg:     Config{Issuer: "%zz", Methods: []string{"RS256"}},
			wantErr: true,
		},
		{
			name:    "empty issuer is an error",
			cfg:     Config{JWKS: "https://keys.example.com/jwks.json", Methods: []string{"RS256"}},
			wantErr: true,
		},
		{
			name:    "empty methods is an error",
			cfg:     Config{Issuer: testIssuer},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewServer(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewServer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if s.jwks != tt.wantJWKS {
				t.Errorf("JWKS = %q, want %q", s.jwks, tt.wantJWKS)
			}
		})
	}
}

// newRunServer returns a Server for running, with the required settings
// filled in.
func newRunServer(t *testing.T, cfg Config) *Server {
	t.Helper()

	cfg.Issuer = testIssuer
	cfg.JWKS = "http://127.0.0.1:0/jwks.json"
	cfg.Methods = []string{"RS256"}

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	return s
}

// listen returns a listener on a free loopback port.
func listen(t *testing.T) net.Listener {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	return l
}

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()

	l := listen(t)
	addr := l.Addr().String()
	_ = l.Close()

	return addr
}

func TestServer_Run(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func(t *testing.T) Config
		wantErr bool
	}{
		{
			name: "cancelled context stops SPOA listener",
			cfg: func(t *testing.T) Config {
				return Config{Listen: "127.0.0.1:0"}
			},
		},
		{
			name: "cancelled context stops SPOA and metrics listeners",
			cfg: func(t *testing.T) Config {
				return Config{Listen: "127.0.0.1:0", MetricsListen: "127.0.0.1:0"}
			},
		},
		{
			name: "SPOA address in use is an error",
			cfg: func(t *testing.T) Config {
				return Config{Listen: listen(t).Addr().String()}
			},
			wantErr: true,
		},
		{
			name: "metrics address in use is an error",
			cfg: func(t *testing.T) Config {
				return Config{Listen: "127.0.0.1:0", MetricsListen: listen(t).Addr().String()}
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newRunServer(t, tt.cfg(t))

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			err := s.Run(ctx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServer_Run_metricsAddressInUseReleasesSPOAAddress(t *testing.T) {
	addr := freeAddr(t)
	s := newRunServer(t, Config{Listen: addr, MetricsListen: listen(t).Addr().String()})

	if err := s.Run(context.Background()); err == nil {
		t.Fatal("Run() succeeded unexpectedly")
	}

	// the SPOA address must be free again
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("SPOA address still in use: %v", err)
	}
	_ = l.Close()
}

func TestServer_run_metrics(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		get      string
		wantCode int
	}{
		{
			name:     "default path serves metrics",
			get:      "/metrics",
			wantCode: http.StatusOK,
		},
		{
			name:     "custom path serves metrics",
			path:     "/custom",
			get:      "/custom",
			wantCode: http.StatusOK,
		},
		{
			name:     "default path is not served when a custom path is set",
			path:     "/custom",
			get:      "/metrics",
			wantCode: http.StatusNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newRunServer(t, Config{MetricsPath: tt.path})
			l, ml := listen(t), listen(t)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- s.run(ctx, l, ml) }()

			resp, err := http.Get("http://" + ml.Addr().String() + tt.get)
			if err != nil {
				cancel()
				t.Fatalf("GET %s: %v", tt.get, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			cancel()
			if err := <-done; err != nil {
				t.Fatalf("run() error = %v", err)
			}

			if resp.StatusCode != tt.wantCode {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantCode)
			}
			if tt.wantCode == http.StatusOK && !strings.Contains(string(body), "go_goroutines") {
				t.Errorf("metrics body does not contain go_goroutines")
			}
		})
	}
}

func TestServer_run_listenerFailureStopsBoth(t *testing.T) {
	tests := []struct {
		name  string
		close func(l, ml net.Listener) net.Listener // closes one, returns the other
	}{
		{
			name:  "metrics listener failure stops SPOA listener",
			close: func(l, ml net.Listener) net.Listener { _ = ml.Close(); return l },
		},
		{
			name:  "SPOA listener failure stops metrics listener",
			close: func(l, ml net.Listener) net.Listener { _ = l.Close(); return ml },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newRunServer(t, Config{})
			l, ml := listen(t), listen(t)

			done := make(chan error, 1)
			go func() { done <- s.run(context.Background(), l, ml) }()

			// let both listeners start serving before failing one
			waitServing(t, ml)
			other := tt.close(l, ml)

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("run() returned nil, want an error")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("run() did not return")
			}

			if err := other.Close(); err == nil {
				t.Error("other listener was still open")
			}
		})
	}
}

// waitServing waits until the metrics listener answers HTTP.
func waitServing(t *testing.T, ml net.Listener) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + ml.Addr().String() + "/metrics")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("metrics listener never served")
}

func BenchmarkServer_handler(b *testing.B) {
	signer := verifytest.NewSigner(b)
	other := verifytest.NewSigner(b)

	claims := func(exp time.Duration, extra map[string]any) map[string]any {
		c := map[string]any{
			"iss": testIssuer,
			"aud": testAudience,
			"exp": time.Now().Add(exp).Unix(),
		}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	email := map[string]any{"email": "user@example.com"}

	s := newTestServer(b, signer, Config{
		Audience:       testAudience,
		Claims:         []string{"email"},
		RequiredClaims: []string{"email"},
	})

	benchmarks := []struct {
		name      string
		jwt       string
		wantValid bool
	}{
		{name: "jwt=valid", jwt: signer.Sign(b, claims(time.Hour, email)), wantValid: true},
		{name: "jwt=badsig", jwt: other.Sign(b, claims(time.Hour, email))},
		{name: "jwt=expired", jwt: signer.Sign(b, claims(-time.Hour, email))},
		{name: "jwt=missingclaim", jwt: signer.Sign(b, claims(time.Hour, nil))},
		{name: "jwt=malformed", jwt: "not-a-jwt"},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			ctx := context.Background()

			// make sure the benchmark measures the outcome it is named for
			req := newRequest(MessageName, map[string]any{"jwt": bm.jwt})
			s.handler(ctx, req)
			want := setVar("jwt_valid", bm.wantValid)
			if got := req.Actions[len(req.Actions)-1]; !reflect.DeepEqual(got, want) {
				b.Fatalf("handler() last action = %#v, want %#v", got, want)
			}
			request.ReleaseRequest(req)

			for b.Loop() {
				req := newRequest(MessageName, map[string]any{"jwt": bm.jwt})
				s.handler(ctx, req)
				request.ReleaseRequest(req)
			}
		})
	}
}
