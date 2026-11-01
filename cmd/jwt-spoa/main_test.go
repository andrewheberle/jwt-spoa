package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not found")
	}

	bin := filepath.Join(t.TempDir(), "jwt-spoa")
	build := exec.Command(goBin, "build", "-ldflags", "-X "+versionVar+"=v9.9.9-test", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		t.Fatalf("running --version: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "jwt-spoa v9.9.9-test" {
		t.Errorf("--version = %q, want %q", got, "jwt-spoa v9.9.9-test")
	}
}
