package jwtspoa

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestExecute(t *testing.T) {
	// a cancelled context makes a valid configuration start and then stop
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	base := []string{"--logger.type", "discard", "--listen", "127.0.0.1:0"}

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		wantErr    bool
		wantStdout string
		wantStderr string
	}{
		{
			name:       "version prints name and version",
			args:       []string{"--version"},
			wantStdout: "jwt-spoa dev\n",
		},
		{
			name:       "unknown flag is an error",
			args:       []string{"--no-such-flag"},
			wantErr:    true,
			wantStderr: "error parsing command line flags",
		},
		{
			name:    "missing issuer is an error",
			args:    base,
			wantErr: true,
		},
		{
			name:    "empty signing methods is an error",
			args:    append([]string{"--jwt.iss", "https://issuer.example.com", "--jwt.methods", ""}, base...),
			wantErr: true,
		},
		{
			name:    "zero JWKS minimum refresh is an error",
			args:    append([]string{"--jwt.iss", "https://issuer.example.com", "--jwt.jwks-min-refresh", "0s"}, base...),
			wantErr: true,
		},
		{
			name:    "JWKS minimum refresh from the environment is used",
			args:    append([]string{"--jwt.iss", "https://issuer.example.com"}, base...),
			env:     map[string]string{"JWT_JWT_JWKS_MIN_REFRESH": "0s"},
			wantErr: true,
		},
		{
			name: "JWKS minimum refresh can be set",
			args: append([]string{"--jwt.iss", "https://issuer.example.com", "--jwt.jwks-min-refresh", "30s"}, base...),
		},
		{
			name: "valid configuration stops cleanly when context is cancelled",
			args: append([]string{"--jwt.iss", "https://issuer.example.com"}, base...),
		},
		{
			name: "issuer can be set from the environment",
			args: base,
			env:  map[string]string{"JWT_JWT_ISS": "https://issuer.example.com"},
		},
		{
			name: "metrics listener stops cleanly when context is cancelled",
			args: append([]string{"--jwt.iss", "https://issuer.example.com", "--metrics.listen", "127.0.0.1:0"}, base...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			var stdout, stderr bytes.Buffer
			err := Execute(cancelled, tt.args, &stdout, &stderr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v (stderr: %s)", err, tt.wantErr, stderr.String())
			}
			if tt.wantStdout != "" && stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
