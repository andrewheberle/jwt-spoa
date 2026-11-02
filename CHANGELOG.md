# Changelog

## [0.4.0](https://github.com/andrewheberle/jwt-spoa/compare/v0.3.1...v0.4.0) (2026-11-02)


### Features

* cache verified JWTs ([#55](https://github.com/andrewheberle/jwt-spoa/issues/55)) ([aacd86d](https://github.com/andrewheberle/jwt-spoa/commit/aacd86d0b1f678ed52352a825d41ccf2cd180502))
* shut down gracefully on SIGINT and SIGTERM ([#46](https://github.com/andrewheberle/jwt-spoa/issues/46)) ([cc6a13d](https://github.com/andrewheberle/jwt-spoa/commit/cc6a13d80561ba87ce92c8c81ceb8237eac7e2f2))


### Bug Fixes

* **deps:** update cgr.dev/chainguard/static:latest docker digest to fc42af3 ([#53](https://github.com/andrewheberle/jwt-spoa/issues/53)) ([61d7546](https://github.com/andrewheberle/jwt-spoa/commit/61d7546294a8a08be3d37790cc954a2bbd95954d))
* **deps:** update module github.com/andrewheberle/configger to v0.2.2 ([#22](https://github.com/andrewheberle/jwt-spoa/issues/22)) ([8d2e6ff](https://github.com/andrewheberle/jwt-spoa/commit/8d2e6ff07bc11ab957190e095cc96465620fdbac))
* **deps:** update module github.com/coreos/go-oidc/v3 to v3.21.0 ([#36](https://github.com/andrewheberle/jwt-spoa/issues/36)) ([fed1256](https://github.com/andrewheberle/jwt-spoa/commit/fed1256d95637bef6acb797cc683de4d59491936))
* **deps:** update module github.com/negasus/haproxy-spoe-go to v1.0.8 ([#35](https://github.com/andrewheberle/jwt-spoa/issues/35)) ([0f98b19](https://github.com/andrewheberle/jwt-spoa/commit/0f98b19fcbfc399956449d7e77cabe8c96883970))
* **deps:** update module github.com/prometheus/client_golang to v1.25.0 ([#23](https://github.com/andrewheberle/jwt-spoa/issues/23)) ([69b8e39](https://github.com/andrewheberle/jwt-spoa/commit/69b8e392c9eace9f7273f6624b1563fd88a9bf16))
* limit how often a failed JWT verification can re-fetch the JWKS ([#51](https://github.com/andrewheberle/jwt-spoa/issues/51)) ([661f55c](https://github.com/andrewheberle/jwt-spoa/commit/661f55cac43227ceb373f70a9e8244e170745245))
* **metrics:** correct request duration help text ([#41](https://github.com/andrewheberle/jwt-spoa/issues/41)) ([b05ed21](https://github.com/andrewheberle/jwt-spoa/commit/b05ed2151a3b91a4c500e53bb62dc520518313d7))
* **spoa:** always set jwt_valid and only set claims for a valid JWT ([#40](https://github.com/andrewheberle/jwt-spoa/issues/40)) ([9b2107c](https://github.com/andrewheberle/jwt-spoa/commit/9b2107ca4867e245236c718e1db7ea523993b76f))
