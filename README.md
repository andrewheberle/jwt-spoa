# jwt-spoa

[![codecov](https://codecov.io/gh/andrewheberle/jwt-spoa/graph/badge.svg?token=XXsp17Pn5L)](https://codecov.io/gh/andrewheberle/jwt-spoa)

This is a Stream Processing Offload Agent (SPOA) for use with HAProxy to
verify an incoming JWT and return the claims. It supports verifying the
JWT against a JWKS URL only at this time.

## Usage

```sh
docker run \
    -e JWT_JWT_ISS="http://idp.example.com" \
	-e JWT_JWT_AUD="expected-jwt-aud" \
    -p 3000:3000 \
	ghcr.io/andrewheberle/jwt-spoa:v0.3.1 # x-release-please-version
```

## HAProxy Integration

As this SPOA handles JSON Web Tokens (JWT's) this is only relevant for HTTP
based proxies.

To integrate JWT handling, add the config to you HAProxy configuration:

```haproxy
# An example HTTP frontend
frontend fe_http
    mode http

    # set transaction level variable for SPOE config
    http-request set-var(txn.jwt) req.hdr("your-jwt-header")

    # send request to SPOE
    filter spoe engine jwt config /etc/haproxy/spoe.cfg
    http-request send-spoe-group jwt verify

    # deny access if JWT was not valid
    acl jwt_valid var(txn.jwt.jwt_valid) -m bool true
    http-request reject unless jwt_valid

    # add further request handling based on claims

# This is the backend for communication with the agent
backend be_spoe
    mode tcp

    timeout connect 5s
    timeout server  5m

    server spoa 127.0.0.1:3000 check
```

A dedicated SPOE configuration file must be created:

```haproxy
[jwt]

spoe-agent jwt
    log global

    timeout hello      2s
    timeout processing 100ms
    timeout idle       3m

    option var-prefix jwt

    groups verify

    use-backend be_spoe

spoe-message jwt-verify
    # Pass the JWT to the SPOA
    args jwt=var(txn.jwt)

spoe-group verify
    messages jwt-verify
```

### Returned Variables

The following variables are returned by the agent to HAProxy:

* txn.PREFIX.jwt_valid (boolean) - If the JWT was valid; always set to `true` or `false`
* txn.PREFIX.claims.CLAIM (string/integer) - Claims in the JWT; only set when `txn.PREFIX.jwt_valid` is `true`

The claims returned in `txn.PREFIX.claims.CLAIM` depend on what is provided to
the SPOA configuration. Claims that are not found are omitted but a warning is
logged.

If any claims specified as required are not found (or cannot be converted to a
supported type) then the JWT is treated as invalid, `txn.PREFIX.jwt_valid` is
returned as `false` and no claims are returned.

### What About Native Verification?

HAProxy has supported verifying and parsing JWT's since v2.5 onwards using its
`jwt_header_query`, `jwt_payload_query` and `jwt_verify` converters, which
requires no external service as is the case with this solution, however
this approach has some limitations as follows:

1. There is no native support for using a JWKS URL to verify a JWT
2. The certificates used to verify the JWT must be fetched and updated via
   HAProxy's management API or available on disk, so external scripts/tooling
   is still required
3. Only the signature of the JWT is verified by the `jwt_verify` converter
4. Verification of the issuer, audience, algorithm and expiry must be
   performed via additional ACLs/converters
5. Claim extraction is via additional converters

As an example, the following two front end configurations are functionally
equivalent, however native verification requires significantly more
configuration and the certificate used to verify the JWT to have been
downloaded and available in PEM format when HAProxy was started/reloaded:

```haproxy
frontend fe_native_jwt
    # extract JWT from request (reject if not found)
    http-request reject unless { http_auth_bearer -m found }
    http-request set-var(txn.jwt) http_auth_bearer
    # extract and check algorithm
    http-request set-var(txn.jwt_alg) var(txn.jwt),jwt_header_query('$.alg')
    http-request deny unless { var(txn.jwt_alg) -m str "RS256" }
    # extract and check issuer
    http-request set-var(txn.jwt_iss) var(txn.jwt),jwt_payload_query('$.iss')
    http-request deny unless { var(txn.jwt_iss) -m str "https://idp.example.com" }
    # extract and check audience
    http-request set-var(txn.jwt_aud) var(txn.jwt),jwt_payload_query('$.aud')
    http-request deny unless { var(txn.jwt_aud) -m reg \[\"allowed-jwd-audience\"\] }
    # extract and check expiry
    http-request set-var(txn.jwt_exp) var(txn.jwt),jwt_payload_query('$.exp','int')
    http-request set-var(txn.now) date
    http-request deny if { var(txn.jwt_exp),sub(txn.now) lt 0 }
    # verify JWT signature
    http-request deny unless { var(txn.jwt),jwt_verify(txn.jwt_alg,"/path/to/pubkey.pem") 1 }
    # deny unless email claim is found
    http-request deny unless { var(txn.jwt),jwt_payload_query('$.email') -m found }
    http-request set-var(txn.jwt.claims.email) var(txn.jwt),jwt_payload_query('$.email')

frontend fe_spoa_jwt
    # extract JWT from request (reject if not found)
    http-request reject unless { http_auth_bearer -m found }
    http-request set-var(txn.jwt) http_auth_bearer
    filter spoe engine jwt config /path/to/spoe.cfg
    http-request send-spoe-group jwt verify
    # check that JWT was valid (checks aud, iss, exp, signature and that an email claim exists)
    http-request deny unless { var(txn.jwt.jwt_valid) -m bool 1 }
```

The config used for the SPOA for the above would be as follows:

```yaml
jwt:
  aud: allowed-jwd-audience
  iss: http://idp.example.com
  jwks: http://idp.example.com/.well-known/jwks.json # default
  requiredclaims: ["email"]
  methods: ["RS256"] # default
```

An important thing to note however is that despite the extra configuration,
native verification is much faster as it avoids handing each request to the
SPOA, so which to use depends on your workload.

### Benchmarks

The two frontends above are benchmarked against each other by sending
requests through a local `haproxy` with both configured, plus a second SPOA
frontend whose agent has the [verification cache](#verification-cache)
enabled. The SPOA agents and the JWKS they fetch run in the benchmark
process:

| JWT               | Method | Verification cache | Time per request | P50 latency | P99 latency |
|-------------------|--------|--------------------|------------------|-------------|-------------|
| Valid             | Native | -                  | 18.5µs           | 0.19ms      | 0.78ms      |
| Valid             | SPOA   | Off                | 83.5µs           | 0.96ms      | 2.33ms      |
| Valid             | SPOA   | On                 | 38.8µs           | 0.37ms      | 1.52ms      |
| Invalid signature | Native | -                  | 20.8µs           | 0.21ms      | 0.89ms      |
| Invalid signature | SPOA   | Off                | 115µs            | 1.33ms      | 2.88ms      |
| Invalid signature | SPOA   | On                 | 119µs            | 1.37ms      | 3.11ms      |

These are the medians of 10 runs, measured on 2 November 2026 with HAProxy
3.2.26 and Go 1.27.3 on a 12 thread Intel Core i5-1335U. Time per request is
from requests sent 12 at a time, so the latencies include time spent queued.

Every request in a run sends the same JWT, so the rows with the verification
cache on are the best case. In practice the benefit depends on how many
requests each client makes with the same JWT. JWTs with an invalid signature
are never cached, so the cache does not change their cost.

The load generator, HAProxy and the SPOA all share the same CPUs, which costs
the SPOA more than native verification as it is an extra process doing work.

To run the benchmarks, with `haproxy` on your `PATH` (or set `HAPROXY_BIN` to
its location) and [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat)
installed:

```sh
go test -tags bench -run '^$' -bench . -count 10 ./internal/benchmark | tee bench.txt
benchstat -col /method bench.txt
```

## Configuration

The agent can be configured via a combination of command line flags, a
configuration file and environment variables.

Options are loaded in the following order, with the ability to override
options from lower levels:

1. Defaults
2. Configuration file
3. Environment variables
4. Command line flags

### Command Line

The following command line options are supported:

| Option                | Type       | Default                        | Description                                                                  |
|-----------------------|------------|--------------------------------|------------------------------------------------------------------------------|
| config                | `string`   |                                | Path to YAML configuration file                                              |
| debug                 | `boolean`  | `false`                        | Enable debug logging                                                         |
| jwt.aud               | `string`   |                                | Audience (aud) expected for JWT verification; not checked if empty           |
| jwt.cache-max-age     | `duration` | `5m`                           | Maximum time a JWT is held in the verification cache; must be greater than 0 |
| jwt.cache-max-entries | `int`      | `10000`                        | Maximum JWT's held in the verification cache; `0` disables the cache         |
| jwt.claims            | `[]string` | `["email"]`                    | Claims to extract from JWT's                                                 |
| jwt.requiredclaims    | `[]string` |                                | Required claims to extract from JWT's                                        |
| jwt.iss               | `string`   |                                | Issuer (iss) claim of the JWT's (required)                                   |
| jwt.jwks              | `string`   | `ISSUER/.well-known/jwks.json` | JWKS URL (required)                                                          |
| jwt.jwks-min-refresh  | `duration` | `1m`                           | Minimum time between JWKS fetches; must be greater than 0                    |
| jwt.methods           | `[]string` | `["RS256"]`                    | Methods/algorithms to use to verify JWT's                                    |
| listen                | `string`   | `127.0.0.1:3000`               | SPOA listen address                                                          |
| logger.type           | `string`   | `auto`                         | Logger type (auto, systemd, json or text)                                    |
| metrics.listen        | `string`   |                                | Listen address for Prometheus metrics                                        |
| metrics.path          | `string`   | `/metrics`                     | Path for Prometheus metrics                                                  |
| version               | `boolean`  | `false`                        | Show version and exit                                                        |

### Environment

All of the above command-line options can be provided as environment
variables as follows:

```sh
# Set issuer and enable metrics on port 9200
JWT_JWT_ISS="http://idp.example.com" JWT_METRICS_LISTEN=":9200" jwt-spoa
```

### Configuration File

A YAML based configuration can be loaded via the `--config` option:

```yaml
jwt:
  iss: http://idp.example.com
debug: false
metrics:
  listen: ':9200'
```

## Key Set Refresh

The JWKS is fetched from the JWKS URL when the first JWT arrives, and the keys
are cached. When a JWT's signature does not verify against the cached keys,
the key set is fetched again in case the identity provider has rotated its
keys.

To stop JWTs with invalid signatures from driving requests at the JWKS URL, a
key set refresh is only sent if the previous fetch started at least
`jwt.jwks-min-refresh` ago (default `1m`). Otherwise the JWT is rejected
without a fetch. Failed fetches count towards this limit too, and each fetch
times out after 10 seconds.

The trade-off is that after the identity provider starts signing with a new
key, JWTs signed with it may be rejected for up to `jwt.jwks-min-refresh`.
Most identity providers publish new keys before signing with them, so this
is rarely seen in practice.

Two Prometheus metrics show this activity:

| Metric                                 | Type      | Description                                                         |
|----------------------------------------|-----------|---------------------------------------------------------------------|
| `jwt_agent_jwks_fetches_total`         | `counter` | JWKS fetches sent, labelled `result` of `success` or `error`        |
| `jwt_agent_jwks_fetches_skipped_total` | `counter` | Key set refreshes refused because the previous fetch was too recent |

An `error` is a failed request or a response other than `200 OK`. A response
that is not a valid key set still counts as a `success`.

## Verification Cache

Verifying a JWT is most of the work the SPOA does for each request, and
clients normally send the same JWT on many requests until it expires. The
verification cache remembers the claim values of each JWT that passed
verification, so a repeat request with the same JWT is answered without
verifying it again. JWTs that fail verification are never cached.

An entry lives until the earlier of the JWT's expiry (`exp`) and
`jwt.cache-max-age` (default `5m`), and the cache holds at most
`jwt.cache-max-entries` JWTs (default `10000`, about 3 to 5MB), evicting the
least recently used when full. Entries are keyed by a SHA-256 hash of the
JWT, so the cache holds no usable tokens. Set `jwt.cache-max-entries` to `0`
to disable the cache.

The trade-off is that a cached JWT keeps passing for up to
`jwt.cache-max-age` after its signing key is withdrawn from the JWKS. Even
without the cache a withdrawn key keeps working until the next
[key set refresh](#key-set-refresh), so lower `jwt.cache-max-age` if you need
withdrawn keys to take effect sooner.

When the cache is enabled, three Prometheus metrics show its activity:

| Metric                                         | Type      | Description                                                                       |
|------------------------------------------------|-----------|-----------------------------------------------------------------------------------|
| `jwt_agent_verification_cache_lookups_total`   | `counter` | Lookups, labelled `result` of `hit` or `miss`; finding an expired entry is a miss |
| `jwt_agent_verification_cache_evictions_total` | `counter` | Entries removed, labelled `reason` of `capacity` or `expired`                     |
| `jwt_agent_verification_cache_entries`         | `gauge`   | JWTs held in the cache                                                            |

## Shutdown

On `SIGINT` or `SIGTERM` (for example from `systemctl stop`) the service stops
gracefully and exits with status `0`:

1. The SPOA listener stops accepting new connections. Connections from HAProxy
   that are already open are not drained, and any JWT verification still in
   progress is cancelled.
2. The metrics listener, if enabled, is shut down, waiting up to 2 seconds for
   in-flight scrapes to finish.

A second `SIGINT` or `SIGTERM` during shutdown stops the service immediately.

## Logging

By default the service will log to `stderr` in one of two formats based on the
default of `auto`:

1. If running under systemd it will output in a format expected by
   `sd_journal_stream_fd`:

	```text
	<LEVEL> MESSAGE KEY=VALUE...
	```
2. Otherwise it will output as text using `slog.NewTextHandler`

The supported options for `logger.type` are:

* `auto`: Detects if the service is being started by systemd (default)
* `discard`: Disables logging using `slog.DiscardHandler`
* `json`: Outputs as JSON using `slog.NewJsonHandler`
* `systemd`: Outputs in `sd_journal_stream_fd` format using a custom
  `slog.Handler`
* `text`: Outputs as text using `slog.NewTextHandler`
