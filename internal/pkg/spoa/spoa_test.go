package spoa

import (
	"reflect"
	"testing"
	"time"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/verify"
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

// newTestServer returns a Server whose verifier checks JWTs against signer
// rather than a remote JWKS.
func newTestServer(t *testing.T, signer *verifytest.Signer, opts ...ServerOption) *Server {
	t.Helper()

	s, err := NewServer("127.0.0.1:0", "http://127.0.0.1:0/jwks.json", testIssuer, opts...)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })

	s.verifier = verify.New(testIssuer, signer.KeySet(), s.verifyOpts...)

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
		opts    []ServerOption
		message string
		values  map[string]any
		want    action.Actions
	}{
		{
			name: "valid JWT sets claims then jwt_valid true",
			opts: []ServerOption{
				WithAudience(testAudience),
				WithClaims([]string{"email", "admin"}),
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
			opts:    []ServerOption{WithAudience(testAudience)},
			message: MessageName,
			values:  map[string]any{"jwt": other.Sign(t, claims(nil))},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
		{
			name: "missing required claim sets no claims and jwt_valid false",
			opts: []ServerOption{
				WithAudience(testAudience),
				WithClaims([]string{"a_claim"}),
				WithRequiredClaims([]string{"email"}),
			},
			message: MessageName,
			values:  map[string]any{"jwt": signer.Sign(t, claims(map[string]any{"a_claim": "a"}))},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
		{
			name:    "missing jwt-verify message sets jwt_valid false",
			opts:    []ServerOption{WithAudience(testAudience)},
			message: "something-else",
			values:  map[string]any{"jwt": signer.Sign(t, claims(nil))},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
		{
			name:    "missing jwt key sets jwt_valid false",
			opts:    []ServerOption{WithAudience(testAudience)},
			message: MessageName,
			values:  map[string]any{"token": signer.Sign(t, claims(nil))},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
		{
			name:    "jwt of wrong type sets jwt_valid false",
			opts:    []ServerOption{WithAudience(testAudience)},
			message: MessageName,
			values:  map[string]any{"jwt": 42},
			want:    action.Actions{setVar("jwt_valid", false)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, signer, tt.opts...)
			req := newRequest(tt.message, tt.values)
			defer request.ReleaseRequest(req)

			s.handler(req)

			if !reflect.DeepEqual(req.Actions, tt.want) {
				t.Errorf("handler() actions = %#v, want %#v", req.Actions, tt.want)
			}
		})
	}
}
