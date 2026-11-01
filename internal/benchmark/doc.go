// Package benchmark compares JWT verification by this SPOA with native
// verification by HAProxy's jwt_* converters, sending requests through a
// local haproxy binary.
//
// The benchmark is behind the bench build tag and is run by hand:
//
//	go test -tags bench -run '^$' -bench . -count 10 ./internal/benchmark
//
// It uses the haproxy binary named by HAPROXY_BIN, or found on PATH, and is
// skipped if there is none.
package benchmark
