// Package verifytest provides helpers for testing code that uses JWT
// verification, without a network or an identity provider.
package verifytest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Signer signs JWTs with a freshly generated RSA key.
type Signer struct {
	key *rsa.PrivateKey
}

// NewSigner returns a Signer with a new 2048-bit RSA key.
func NewSigner(t testing.TB) *Signer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	return &Signer{key: key}
}

// KeySet returns a key set that verifies JWTs signed by s.
func (s *Signer) KeySet() oidc.KeySet {
	return &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&s.key.PublicKey}}
}

// JWKS returns a JSON Web Key Set holding the public key of s.
func (s *Signer) JWKS(t testing.TB) []byte {
	t.Helper()

	enc := base64.RawURLEncoding
	set := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"n":   enc.EncodeToString(s.key.N.Bytes()),
			"e":   enc.EncodeToString(big.NewInt(int64(s.key.E)).Bytes()),
		}},
	}

	b, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("encoding JWKS: %v", err)
	}

	return b
}

// PublicKeyPEM returns the public key of s as a PEM encoded PKIX public key.
func (s *Signer) PublicKeyPEM(t testing.TB) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		t.Fatalf("encoding public key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Sign returns an RS256-signed JWT carrying claims.
func (s *Signer) Sign(t testing.TB, claims map[string]any) string {
	t.Helper()

	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatalf("encoding JWT header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encoding JWT payload: %v", err)
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}

	return signingInput + "." + enc.EncodeToString(sig)
}
