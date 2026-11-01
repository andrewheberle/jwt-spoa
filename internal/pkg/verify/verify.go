// Package verify implements JWT verification: checking a JWT's signature,
// issuer, audience, signing method and expiry, then applying the claim rules
// to produce the claim values to expose to HAProxy.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	// ErrInvalidToken is returned when the JWT fails verification.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidClaims is returned when the claims of a verified JWT cannot be decoded.
	ErrInvalidClaims = errors.New("invalid claims")
	// ErrMissingRequiredClaim is returned when a required claim is absent.
	ErrMissingRequiredClaim = errors.New("missing required claim")
)

// Verifier performs JWT verification against an issuer and key set.
type Verifier struct {
	issuer         string
	keys           oidc.KeySet
	config         *oidc.Config
	claims         []string
	requiredClaims []string
	logger         *slog.Logger

	verifier *oidc.IDTokenVerifier
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithAudience sets the audience (aud) the JWT must contain. Without it, the
// audience is not checked.
func WithAudience(aud string) Option {
	return func(v *Verifier) {
		v.config.ClientID = aud
	}
}

// WithValidMethods sets the accepted signing methods. The default is RS256.
func WithValidMethods(methods []string) Option {
	return func(v *Verifier) {
		v.config.SupportedSigningAlgs = methods
	}
}

// WithClaims adds claims to extract when present.
func WithClaims(claims []string) Option {
	return func(v *Verifier) {
		v.claims = merge(v.claims, claims)
	}
}

// WithRequiredClaims adds claims that must be present for the JWT to be
// valid. Required claims are also extracted.
func WithRequiredClaims(claims []string) Option {
	return func(v *Verifier) {
		v.requiredClaims = merge(v.requiredClaims, claims)
		v.claims = merge(v.claims, claims)
	}
}

// WithLogger sets the logger used for non-fatal problems, such as a missing
// optional claim. By default nothing is logged.
func WithLogger(logger *slog.Logger) Option {
	return func(v *Verifier) {
		v.logger = logger
	}
}

// New returns a Verifier for JWTs from issuer, whose signatures are checked
// against keys. The issuer must not be empty and at least one signing method
// must be accepted.
func New(issuer string, keys oidc.KeySet, opts ...Option) (*Verifier, error) {
	if issuer == "" {
		return nil, errors.New("issuer must be provided")
	}

	v := &Verifier{
		issuer:         issuer,
		keys:           keys,
		config:         &oidc.Config{SupportedSigningAlgs: []string{oidc.RS256}},
		claims:         make([]string, 0),
		requiredClaims: make([]string, 0),
		logger:         slog.New(slog.DiscardHandler),
	}

	for _, o := range opts {
		o(v)
	}

	if len(v.config.SupportedSigningAlgs) == 0 {
		return nil, errors.New("at least one signing method must be provided")
	}

	// go-oidc rejects every JWT when no audience is set unless told to skip
	// the check
	v.config.SkipClientIDCheck = v.config.ClientID == ""

	v.verifier = oidc.NewVerifier(v.issuer, v.keys, v.config)

	return v, nil
}

// Verify verifies the signed JWT and returns its claim values, keyed by claim
// name. Only configured claims that are present are returned. Each value is a
// bool, int or string.
//
// Any error means the JWT is invalid, and no claim values are returned.
// Errors wrap ErrInvalidToken, ErrInvalidClaims or ErrMissingRequiredClaim.
func (v *Verifier) Verify(ctx context.Context, signed string) (map[string]any, error) {
	parsed, err := v.verifier.Verify(ctx, signed)
	if err != nil {
		return nil, fmt.Errorf("verifying JWT: %w: %w", ErrInvalidToken, err)
	}

	var all map[string]json.RawMessage
	if err := parsed.Claims(&all); err != nil {
		return nil, fmt.Errorf("decoding claims: %w: %w", ErrInvalidClaims, err)
	}

	values := make(map[string]any, len(v.claims))
	for _, claim := range v.claims {
		raw, ok := all[claim]
		if !ok {
			if slices.Contains(v.requiredClaims, claim) {
				return nil, fmt.Errorf("%w: %s", ErrMissingRequiredClaim, claim)
			}
			v.logger.Warn("an expected claim was missing", "claim", claim)
			continue
		}

		value, err := toValue(raw)
		if err != nil {
			if slices.Contains(v.requiredClaims, claim) {
				return nil, fmt.Errorf("converting required claim %s: %w: %w", claim, ErrInvalidClaims, err)
			}
			v.logger.Warn("problem converting claim value to a supported type", "claim", claim, "error", err)
			continue
		}
		values[claim] = value
	}

	return values, nil
}

// merge appends extra to list and returns it sorted with no duplicates.
func merge(list, extra []string) []string {
	list = append(list, extra...)
	slices.Sort(list)
	return slices.Compact(list)
}

// toValue converts a raw JSON claim to a claim value supported by SPOE.
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
		// non-whole numbers fall back to a string representation
		return fmt.Sprintf("%v", t), nil
	case nil:
		return "", nil
	default:
		// array or object - re-marshal to a compact JSON string
		b, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	}
}
