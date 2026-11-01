package spoa

import (
	"reflect"
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
func newTestServer(t *testing.T, signer *verifytest.Signer, cfg Config) *Server {
	t.Helper()

	cfg.Listen = "127.0.0.1:0"
	cfg.Issuer = testIssuer
	cfg.JWKS = "http://127.0.0.1:0/jwks.json"
	cfg.Methods = []string{"RS256"}

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })

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

			s.handler(req)

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
			t.Cleanup(func() { _ = s.Shutdown() })

			if s.jwks != tt.wantJWKS {
				t.Errorf("JWKS = %q, want %q", s.jwks, tt.wantJWKS)
			}
		})
	}
}
