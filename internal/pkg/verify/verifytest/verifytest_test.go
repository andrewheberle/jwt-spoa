package verifytest

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestSigner_JWKS(t *testing.T) {
	signer := NewSigner(t)
	other := NewSigner(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(signer.JWKS(t))
	}))
	defer srv.Close()

	keys := oidc.NewRemoteKeySet(context.Background(), srv.URL)

	tests := []struct {
		name    string
		signer  *Signer
		wantErr bool
	}{
		{name: "JWT signed by the key set's signer verifies", signer: signer},
		{name: "JWT signed by another signer does not verify", signer: other, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt := tt.signer.Sign(t, map[string]any{"sub": "user-1"})

			if _, err := keys.VerifySignature(context.Background(), jwt); (err != nil) != tt.wantErr {
				t.Errorf("VerifySignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSigner_PublicKeyPEM(t *testing.T) {
	signer := NewSigner(t)

	block, _ := pem.Decode(signer.PublicKeyPEM(t))
	if block == nil {
		t.Fatal("PublicKeyPEM() did not return a PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM block type = %q, want %q", block.Type, "PUBLIC KEY")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}
	if !signer.key.PublicKey.Equal(pub) {
		t.Error("PublicKeyPEM() does not hold the signer's public key")
	}
}
