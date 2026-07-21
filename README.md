# jwt-spoa

[![codecov](https://codecov.io/gh/andrewheberle/jwt-spoa/graph/badge.svg?token=XXsp17Pn5L)](https://codecov.io/gh/andrewheberle/jwt-spoa)

This is a Stream Processing Offload Agent (SPOA) for use with HAProxy to
verify an incoming JWT and return the claims. It supports verifying the
JWT against a JWKS URL only at this time.

## HAProxy Integration

As this SPOA handles JSON Web Tokens (JWT's) this is only relevant for HTTP
based proxies.

To integrate JWT handling, add the config to you HAProxy configuration:

```
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

```
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
    args jwt=var(txn.jwt)

spoe-group verify
    messages jwt-verify

	# Pass the JWT to the SPOA
    args jwt=var(txn.jwt)

spoe-group verify
    messages jwt-verify
```

### Returned Variables

The following variables are returned by the agent to HAProxy:

* txn.PREFIX.jwt_valid (boolean) - If the JWT was valid
* txn.PREFIX.claims.CLAIM (string/integer) - Claims in the JWT

The claims returned in `txn.PREFIX.claims.CLAIM` depend on what is provided to
the SPOA configuration. Claims that are not found are omitted but a warning is
logged.

If any claims specified as required are not found then parsing of the JWT is
stopped and `txn.PREFIX.jwt_valid` is returned as `false`, so in this case
there may or may not be some claims returned depending on the order in which
they were processed.

### Why Not Use Native JWT Fetches?

HAProxy has supported verifying and parsing JWT's since v2.5 onwards which
requires no external service as is the case with this solution, however
this approach has some limitations as follows:

1. There is no native support for using a JWKS URL to verify a JWT
2. The certificates used to verify the JWT must be fetched and updated via
   HAProxy's management API or available on disk, so external scripts/tooling
   is still required
3. Only the signature of the JWT is verified by the `jwt_verify` fetch method
4. Verification of the issuer, audience, algorithm and expiry must be
   performed via additional ACLs/fetches
5. Claim extraction is via additional fetches

As an example, the following two front end configurations are functionally
equivalent, however the built-in JWT handling requires significantly more
configuration and the certificate used to verify the JWT to have been
downloaded and available in PEM format when HAProxy was started/reloaded:

```
frontend fe_builtin_jwt
	# extract JWT from request
	http-request set-var(txn.jwt) http_auth_bearer
	# extract and check algorithm
	http-request set-var(txn.jwt_alg) var(txn.jwt),jwt_header_query('$.alg')
	http-request deny unless { var(txn.jwt_alg) -m str "RS256" }
	# extract and check issuer
	http-request set-var(txn.jwt_iss) var(txn.jwt),jwt_header_query('$.iss')
	http-request deny unless { var(txn.jwt_iss) -m str "https://idp.example.com" }
	# extract and check audience
	http-request set-var(txn.jwt_aud) var(txn.jwt),jwt_header_query('$.aud')
	http-request deny unless { var(txn.jwt_aud) -m str "allowed-jwd-audience" }
	# extract and check expiry
	http-request set-var(txn.jwt_exp) var(txn.jwt),jwt_payload_query('$.exp','int')
  	http-request set-var(txn.now) date
	http-request deny unless { var(txn.jwt_exp),sub(txn.now) lt 0 }
	# verify JWT signature
	http-request deny unless { var(txn.jwt),jwt_verify(txn.jwt_alg,"/path/to/pubkey.pem") 1 }
	# deny unless email claim is found
	http-request deny unless { var(txn.jwt),jwt_payload_query('$.email') -m found }

frontend fe_spoa_jwt
	# extract JWT from request
	http-request set-var(txn.jwt) http_auth_bearer
	filter spoe engine jwt config /path/to/spoe.cfg
	http-request send-spoe-group jwt verify
	# check that JWT was valid (checks aud, iss, exp, signature and that an email claim exists)
	http-request deny unless { var(txn.jwt.jwt_valid) -m bool true }
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

| Option             | Type       | Default                        | Description                                  |
|--------------------|------------|--------------------------------|----------------------------------------------|
| config             | `string`   |                                | Path to YAML configuration file              |
| debug              | `boolean`  | `false`                        | Enable debug logging                         |
| jwt.aud            | `string`   |                                | Audience (aud) expected for JWT verification |
| jwt.claims         | `[]string` | `["email"]`                    | Claims to extract from JWT's                 |
| jwt.requiredclaims | `[]string` |                                | Required claims to extract from JWT's        |
| jwt.iss            | `string`   |                                | Issuer (iss) claim of the JWT's (required)   |
| jwt.jwks           | `string`   | `ISSUER/.well-known/jwks.json` | JWKS URL (required)                          |
| jwt.methods        | `[]string` | `["RS256"]`                    | Methods/algorithms to use to verify JWT's    |
| listen             | `string`   | `127.0.0.1:3000`               | SPOA listen address                          |
| logger.type        | `string`   | `auto`                         | Logger type (auto, systemd, json or text)    |
| metrics.listen     | `string`   |                                | Listen address for Prometheus metrics        |
| metrics.path       | `string`   | `/metrics`                     | Path for Prometheus metrics                  |
| version            | `boolean`  | `false`                        | Show version and exit                        |

### Environment

All of the above command-line options can be provided as environment
variables as follows:

```sh
# Disable cache and enable metrics on port 9200
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
