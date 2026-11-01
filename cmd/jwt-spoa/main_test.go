package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// versionVar is where the release build injects the version.
const versionVar = "github.com/andrewheberle/jwt-spoa/internal/version.Version"

// TestVersionInjection checks that the -X path used by GoReleaser names the
// version variable, so releases do not silently report "dev".
func TestVersionInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}

	goreleaser, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}
	m := regexp.MustCompile(`-X (\S+)=\{\{ \.Version \}\}`).FindSubmatch(goreleaser)
	if m == nil {
		t.Fatal(".goreleaser.yaml has no -X ...={{ .Version }} ldflag")
	}
	if got := string(m[1]); got != versionVar {
		t.Fatalf(".goreleaser.yaml injects %q, want %q", got, versionVar)
	}

	bin := buildBinary(t, "-X "+versionVar+"=v9.9.9-test")

	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		t.Fatalf("running --version: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "jwt-spoa v9.9.9-test" {
		t.Errorf("--version = %q, want %q", got, "jwt-spoa v9.9.9-test")
	}
}

// buildBinary builds jwt-spoa with ldflags and returns its path.
func buildBinary(t *testing.T, ldflags string) string {
	t.Helper()

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not found")
	}

	bin := filepath.Join(t.TempDir(), "jwt-spoa")
	build := exec.Command(goBin, "build", "-ldflags", ldflags, "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	return bin
}

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	return addr
}

// TestShutdownOnSignal checks that SIGINT and SIGTERM stop jwt-spoa cleanly
// with exit status 0.
func TestShutdownOnSignal(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}

	bin := buildBinary(t, "")

	tests := []struct {
		name   string
		signal syscall.Signal
	}{
		{name: "SIGINT", signal: syscall.SIGINT},
		{name: "SIGTERM", signal: syscall.SIGTERM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := freeAddr(t)
			cmd := exec.Command(bin,
				"--logger.type", "discard",
				"--jwt.iss", "https://issuer.example.com",
				"--listen", "127.0.0.1:0",
				"--metrics.listen", metrics,
			)
			if err := cmd.Start(); err != nil {
				t.Fatalf("starting jwt-spoa: %v", err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			t.Cleanup(func() { _ = cmd.Process.Kill() })

			waitServing(t, fmt.Sprintf("http://%s/metrics", metrics), done)

			if err := cmd.Process.Signal(tt.signal); err != nil {
				t.Fatalf("sending %s: %v", tt.name, err)
			}

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("jwt-spoa exited with %v after %s, want exit status 0", err, tt.name)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("jwt-spoa did not exit after %s", tt.name)
			}
		})
	}
}

// waitServing waits until url answers, failing if the process exits first.
func waitServing(t *testing.T, url string, done <-chan error) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("jwt-spoa exited early: %v", err)
		default:
		}

		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("jwt-spoa never started serving")
}
