package verify_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/verify"
	"github.com/andrewheberle/jwt-spoa/internal/pkg/verify/verifytest"
)

const (
	issuer   = "https://issuer.example.com"
	audience = "jwt-spoa"
)

func validClaims(extra map[string]any) map[string]any {
	c := map[string]any{
		"iss": issuer,
		"aud": audience,
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func TestVerifier_Verify(t *testing.T) {
	signer := verifytest.NewSigner(t)
	other := verifytest.NewSigner(t)

	tests := []struct {
		name    string
		opts    []verify.Option
		signer  *verifytest.Signer
		claims  map[string]any
		want    map[string]any
		wantErr error
	}{
		{
			name:   "valid token with no claims configured",
			opts:   []verify.Option{verify.WithAudience(audience)},
			claims: validClaims(nil),
			want:   map[string]any{},
		},
		{
			name: "configured claims are converted to claim values",
			opts: []verify.Option{
				verify.WithAudience(audience),
				verify.WithClaims([]string{"email", "admin", "level", "groups", "score"}),
			},
			claims: validClaims(map[string]any{
				"email":  "user@example.com",
				"admin":  true,
				"level":  3,
				"groups": []string{"a", "b"},
				"score":  98.5,
			}),
			want: map[string]any{
				"email":  "user@example.com",
				"admin":  true,
				"level":  3,
				"groups": `["a","b"]`,
				"score":  "98.5",
			},
		},
		{
			name: "missing optional claim is omitted",
			opts: []verify.Option{
				verify.WithAudience(audience),
				verify.WithClaims([]string{"email", "name"}),
			},
			claims: validClaims(map[string]any{"email": "user@example.com"}),
			want:   map[string]any{"email": "user@example.com"},
		},
		{
			name: "present required claim is returned",
			opts: []verify.Option{
				verify.WithAudience(audience),
				verify.WithRequiredClaims([]string{"email"}),
			},
			claims: validClaims(map[string]any{"email": "user@example.com"}),
			want:   map[string]any{"email": "user@example.com"},
		},
		{
			name: "missing required claim returns no claims and error",
			opts: []verify.Option{
				verify.WithAudience(audience),
				verify.WithClaims([]string{"a_claim", "z_claim"}),
				verify.WithRequiredClaims([]string{"email"}),
			},
			claims:  validClaims(map[string]any{"a_claim": "a", "z_claim": "z"}),
			wantErr: verify.ErrMissingRequiredClaim,
		},
		{
			name:    "signature from another key is rejected",
			opts:    []verify.Option{verify.WithAudience(audience)},
			signer:  other,
			claims:  validClaims(nil),
			wantErr: verify.ErrInvalidToken,
		},
		{
			name:    "wrong issuer is rejected",
			opts:    []verify.Option{verify.WithAudience(audience)},
			claims:  validClaims(map[string]any{"iss": "https://other.example.com"}),
			wantErr: verify.ErrInvalidToken,
		},
		{
			name:    "wrong audience is rejected",
			opts:    []verify.Option{verify.WithAudience(audience)},
			claims:  validClaims(map[string]any{"aud": "someone-else"}),
			wantErr: verify.ErrInvalidToken,
		},
		{
			name:   "no audience configured accepts any audience",
			claims: validClaims(map[string]any{"aud": "anyone"}),
			want:   map[string]any{},
		},
		{
			name: "disallowed signing method is rejected",
			opts: []verify.Option{
				verify.WithAudience(audience),
				verify.WithValidMethods([]string{"ES256"}),
			},
			claims:  validClaims(nil),
			wantErr: verify.ErrInvalidToken,
		},
		{
			name:    "expired token is rejected",
			opts:    []verify.Option{verify.WithAudience(audience)},
			claims:  validClaims(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
			wantErr: verify.ErrInvalidToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.signer
			if s == nil {
				s = signer
			}
			v := verify.New(issuer, signer.KeySet(), tt.opts...)

			got, err := v.Verify(context.Background(), s.Sign(t, tt.claims))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Verify() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestVerifier_Verify_malformed(t *testing.T) {
	signer := verifytest.NewSigner(t)
	v := verify.New(issuer, signer.KeySet(), verify.WithAudience(audience))

	if _, err := v.Verify(context.Background(), "not-a-jwt"); !errors.Is(err, verify.ErrInvalidToken) {
		t.Fatalf("Verify() error = %v, want %v", err, verify.ErrInvalidToken)
	}
}
