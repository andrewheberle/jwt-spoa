# Cache verified JWTs by default

Clients send the same JWT on many requests until it expires, and verifying it again each time is most of the SPOA's per-request cost: checking the RSA signature and parsing the token. The verification cache remembers the claim values of JWTs that passed, keyed by the SHA-256 of the JWT, for the earlier of the JWT's `exp` and `jwt.cache-max-age` (default `5m`). It holds at most `jwt.cache-max-entries` JWTs (default `10000`, about 3 to 5MB), evicting the least recently used. It is on by default; setting `jwt.cache-max-entries` to `0` turns it off.

The cost is that a cached JWT keeps passing for up to `jwt.cache-max-age` after its signing key is withdrawn from the JWKS. Without the cache, a withdrawn key already keeps working until the next key set refresh, which only happens after a JWT fails signature verification, so the cache lengthens an existing window rather than opening a new one.

## Considered Options

- **Off by default**: avoids the longer withdrawn-key window, but most deployments would never turn it on and would keep paying for verification on every request.
- **Caching failures too**: makes a repeated bad JWT cheaper, but anyone can make unlimited distinct bad JWTs to push out good entries, and a cached failure could outlast the key set refresh that would make the JWT valid.
- **Keying by the raw JWT**: saves about 1µs of hashing per request, but keeps every cached bearer token in memory as a usable credential.
- **`hashicorp/golang-lru/v2/expirable`**: does the same job, but adds a module dependency for about 100 lines of standard library code.
- **Collapsing concurrent misses (`singleflight`)**: saves a handful of verifications when a client's first requests with a new JWT arrive together, for extra complexity on every miss.
- **Clearing the cache on a key set refresh**: would make a withdrawn key stop working for cached JWTs as soon as a refresh picks up the change, but couples the JWKS transport to the cache, and refreshes only happen after a failed verification, so their timing is arbitrary anyway. Worth revisiting if `jwt.cache-max-age` proves too coarse.

## Consequences

Repeat requests with a cached JWT skip JWT verification entirely, so a fix to verification only applies to cached JWTs once their entries expire, within `jwt.cache-max-age`. The benchmarks reuse one JWT, so `cache=on` results are the best case; a real hit rate depends on how many requests each client makes per JWT.
