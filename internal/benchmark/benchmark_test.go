//go:build bench

package benchmark

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/spoa"
	"github.com/andrewheberle/jwt-spoa/internal/pkg/verify/verifytest"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "jwt-spoa"
)

// haproxyConfig holds the values for testdata/haproxy.cfg.tmpl.
type haproxyConfig struct {
	NativeAddr     string
	SPOAAddr       string
	AgentAddr      string
	Issuer         string
	Audience       string
	KeyPath        string
	SPOEConfigPath string
}

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(b *testing.B) string {
	b.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	return addr
}

// haproxyBin returns the haproxy binary named by HAPROXY_BIN, or found on
// PATH, and skips the benchmark if there is none.
func haproxyBin(b *testing.B) string {
	b.Helper()

	if bin := os.Getenv("HAPROXY_BIN"); bin != "" {
		return bin
	}

	bin, err := exec.LookPath("haproxy")
	if err != nil {
		b.Skip("haproxy not found on PATH and HAPROXY_BIN not set")
	}

	return bin
}

// startAgent runs the SPOA on addr, checking JWTs against the key set
// served by jwks, until the benchmark ends.
func startAgent(b *testing.B, addr, jwks string) {
	b.Helper()

	s, err := spoa.NewServer(spoa.Config{
		Listen:         addr,
		Issuer:         testIssuer,
		JWKS:           jwks,
		JWKSMinRefresh: time.Minute,
		Audience:       testAudience,
		Methods:        []string{"RS256"},
		Claims:         []string{"email"},
		RequiredClaims: []string{"email"},
	})
	if err != nil {
		b.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	b.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			b.Errorf("Run() error = %v", err)
		}
	})
}

// startHAProxy writes the HAProxy and SPOE config to a temporary directory
// and runs haproxy with it until the benchmark ends.
func startHAProxy(b *testing.B, cfg haproxyConfig, key []byte) {
	b.Helper()

	bin := haproxyBin(b)
	dir := b.TempDir()

	cfg.KeyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cfg.KeyPath, key, 0o600); err != nil {
		b.Fatalf("writing public key: %v", err)
	}

	spoe, err := os.ReadFile(filepath.Join("testdata", "spoe.cfg"))
	if err != nil {
		b.Fatalf("reading SPOE config: %v", err)
	}
	cfg.SPOEConfigPath = filepath.Join(dir, "spoe.cfg")
	if err := os.WriteFile(cfg.SPOEConfigPath, spoe, 0o600); err != nil {
		b.Fatalf("writing SPOE config: %v", err)
	}

	tmpl, err := template.ParseFiles(filepath.Join("testdata", "haproxy.cfg.tmpl"))
	if err != nil {
		b.Fatalf("parsing HAProxy config template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		b.Fatalf("rendering HAProxy config: %v", err)
	}
	cfgPath := filepath.Join(dir, "haproxy.cfg")
	if err := os.WriteFile(cfgPath, buf.Bytes(), 0o600); err != nil {
		b.Fatalf("writing HAProxy config: %v", err)
	}

	var stderr bytes.Buffer
	cmd := exec.Command(bin, "-db", "-f", cfgPath)
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		b.Fatalf("starting haproxy: %v", err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()

	b.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
		if b.Failed() {
			b.Logf("haproxy output:\n%s", stderr.String())
		}
	})

	for _, addr := range []string{cfg.NativeAddr, cfg.SPOAAddr} {
		waitListening(b, addr, exited)
	}
}

// waitListening waits until addr accepts connections, failing if haproxy
// exits first.
func waitListening(b *testing.B, addr string, exited <-chan struct{}) {
	b.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			b.Fatal("haproxy exited during startup")
		default:
		}

		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.Fatalf("haproxy never listened on %s", addr)
}

// get sends a request carrying jwt as a bearer token to url and returns the
// response status code.
func get(client *http.Client, url, jwt string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	// read the body so the connection is reused
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return 0, err
	}

	return resp.StatusCode, nil
}

// percentile returns the p-th percentile of the sorted durations.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(float64(len(sorted)-1)*p)]
}

func BenchmarkVerification(b *testing.B) {
	signer := verifytest.NewSigner(b)
	other := verifytest.NewSigner(b)

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(signer.JWKS(b))
	}))
	b.Cleanup(jwks.Close)

	cfg := haproxyConfig{
		NativeAddr: freeAddr(b),
		SPOAAddr:   freeAddr(b),
		AgentAddr:  freeAddr(b),
		Issuer:     testIssuer,
		Audience:   testAudience,
	}
	startAgent(b, cfg.AgentAddr, jwks.URL)
	startHAProxy(b, cfg, signer.PublicKeyPEM(b))

	// the native frontend matches the audience as a JSON array
	claims := map[string]any{
		"iss":   testIssuer,
		"aud":   []string{testAudience},
		"exp":   time.Now().Add(time.Hour).Unix(),
		"email": "user@example.com",
	}

	client := &http.Client{
		Transport: &http.Transport{MaxIdleConnsPerHost: 1024},
		Timeout:   5 * time.Second,
	}
	b.Cleanup(client.CloseIdleConnections)

	methods := []struct {
		name string
		addr string
	}{
		{name: "method=native", addr: cfg.NativeAddr},
		{name: "method=spoa", addr: cfg.SPOAAddr},
	}
	jwts := []struct {
		name       string
		jwt        string
		wantStatus int
	}{
		{name: "jwt=valid", jwt: signer.Sign(b, claims), wantStatus: http.StatusOK},
		{name: "jwt=badsig", jwt: other.Sign(b, claims), wantStatus: http.StatusForbidden},
	}
	for _, m := range methods {
		b.Run(m.name, func(b *testing.B) {
			url := "http://" + m.addr + "/"

			for _, j := range jwts {
				b.Run(j.name, func(b *testing.B) {
					// warm up: fills the SPOA's key set cache, opens the SPOE
					// connections and checks the expected outcome
					status, err := get(client, url, j.jwt)
					if err != nil {
						b.Fatalf("warm up request error = %v", err)
					}
					if status != j.wantStatus {
						b.Fatalf("warm up request status = %d, want %d", status, j.wantStatus)
					}

					var (
						mu         sync.Mutex
						latencies  []time.Duration
						unexpected atomic.Int64
						firstErr   atomic.Pointer[error]
					)

					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						local := make([]time.Duration, 0, 1024)
						for pb.Next() {
							start := time.Now()
							status, err := get(client, url, j.jwt)
							local = append(local, time.Since(start))
							if err != nil {
								firstErr.CompareAndSwap(nil, &err)
								continue
							}
							if status != j.wantStatus {
								unexpected.Add(1)
							}
						}

						mu.Lock()
						latencies = append(latencies, local...)
						mu.Unlock()
					})
					b.StopTimer()

					if err := firstErr.Load(); err != nil {
						b.Fatalf("request error = %v", *err)
					}
					if n := unexpected.Load(); n > 0 {
						b.Fatalf("%d of %d requests did not return status %d", n, len(latencies), j.wantStatus)
					}

					slices.Sort(latencies)
					b.ReportMetric(float64(percentile(latencies, 0.50).Nanoseconds()), "p50-ns")
					b.ReportMetric(float64(percentile(latencies, 0.99).Nanoseconds()), "p99-ns")
				})
			}
		})
	}
}
