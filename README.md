# jwt-spoa

This is a Stream Processing Offload Agent (SPOA) for use with HAProxy to
verify an incoming JWT and return the claims. It supports verifying the
JWT against a JWKS URL only at this time.

## HAProxy Integration

Add the config to you HAProxy configuration:

```
# An example HTTP frontend
frontend fe_http
	mode http

	acl allowed_asn var(txn.jwt_valid) -m bool

	http-request set-var(txn.jwt) http_auth_bearer()

	filter spoe engine jwt config /etc/haproxy/spoe.cfg

	http-request send-spoe-group jwt verify
	http-request reject unless allowed_asn

	# the rest of your frontend config is unchanged

# This is the backend for communication with the agent
backend be_spoe
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

	# This must match the backend name in the main config
    use-backend be_spoe

spoe-message jwt-verifiy
	# Pass the JWT to the SPOA
    args jwt=var(txn.jwt)

spoe-group verifiy
    messages jwt-verifiy
```

### Returned Variables

The following variables are returned by the agent to HAProxy:

* txn.PREFIX.jwt_valid (boolean) - If the JWT was valid
* txn.PREFIX.claims.CLAIM (string/integer) - Claims in the JWT

The claims returned in `txn.PREFIX.claims.CLAIM` depend on what is provided to
the SPO configuration. Claims that are not found are omitted but a warning is
logged.

## Configuratuon

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

| Option         | Type       | Default                             | Description                                        |
|----------------|------------|-------------------------------------|----------------------------------------------------|
| config         | `string`   |                                     | Path to YAML configuration file                    |
| debug          | `boolean`  | `false`                             | Enable debug logging                               |
| jwt.aud        | `string`   |                                     | Audience (aud) expected for JWT verification       |
| jwt.claims     | `[]string` | `["email"]`                         | Additional claims to extract from JWT's            |
| jwt.iss        | `string`   |                                     | Issuer (iss) claim of the JWT's (required)         |
| jwt.jwks       | `string`   | `ISSUER/.well-known/jwks.json`      | JWKS URL (required)                                |
| jwt.methods    | `[]string` | `["RS256"]`                         | Methods/algorithms to use to verify JWT's          |
| listen         | `string`   | `127.0.0.1:3000`                    | SPOA listen address                                |
| logger.type    | `string`   | `auto`                              | Logger type (auto, systemd, json or text)          |
| metrics.listen | `string`   |                                     | Listen address for Prometheus metrics              |
| metrics.path   | `string`   | `/metrics`                          | Path for Prometheus metrics                        |
| version        | `boolean`  | `false`                             | Show version and exit                              |

### Environment

All of the above command-line options can be provided as environemnt
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
