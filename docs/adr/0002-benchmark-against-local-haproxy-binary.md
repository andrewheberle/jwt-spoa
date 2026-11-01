# Benchmark against a local HAProxy binary, run by hand

The comparison between this SPOA and native verification is a Go benchmark in `internal/benchmark`, behind the `bench` build tag. It starts the `haproxy` binary found on `PATH` (or `HAPROXY_BIN`), runs the SPOA in-process and serves the JWKS from `httptest`, then sends load through both frontends from the same test binary. It is run by hand and its results are published in the README. CI only runs the in-process microbenchmarks once, so they keep compiling and working.

## Considered Options

- **testcontainers-go with `haproxy:lts`**: pins the HAProxy version and needs no local install, but adds a module dependency, needs Docker, and puts container networking between HAProxy and both the client and the SPOA, which skews the comparison.
- **Docker Compose with an external load tool (`oha`, `k6`)**: easy to follow, but lives outside `go test`, so it cannot reuse the test signer and fakes or report results in a form `benchstat` reads.
- **Regression detection in CI**: needs stored baselines, and shared GitHub runners are too noisy for alerts to be trusted.

## Consequences

Published numbers depend on the HAProxy version and the host they were measured on, so the README records both with the results. The load generator, HAProxy and the SPOA share the same CPUs, which costs the SPOA more than native verification since it is an extra process doing work.
