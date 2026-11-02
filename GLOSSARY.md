# jwt-spoa

An HAProxy stream processing offload agent that checks the JWT on each request and hands the result and selected claims back to HAProxy.

## Language

**JWT verification**:
Checking a JWT's signature, issuer, audience, signing method and expiry, then applying the claim rules. A JWT passes only if every check passes.
_Avoid_: validation, authentication, parsing

**Claim**:
A named field in a verified JWT that has been configured to be exposed to HAProxy as `txn.<prefix>.claims.<name>`.
_Avoid_: attribute, field

**Required claim**:
A claim that must be present for the JWT to pass verification.
_Avoid_: mandatory claim

**Claim value**:
A claim converted to a type HAProxy can hold: a boolean, an integer, or a string (compact JSON for arrays and objects).
_Avoid_: claim data

**Key set refresh**:
Fetching the JWKS again from the JWKS URL after a JWT fails signature verification against the cached keys, in case the keys have rotated. Limited to one fetch per `jwt.jwks-min-refresh`.
_Avoid_: reload, rotate, sync

**Native verification**:
Checking a JWT inside HAProxy using only its `jwt_header_query`, `jwt_payload_query` and `jwt_verify` converters, with no SPOA.
_Avoid_: native fetches, builtin, built-in JWT handling

**Verification cache**:
Remembered results of JWT verification for JWTs that passed, so a repeat request with the same JWT returns the same claim values without verifying again. An entry never outlives the JWT's `exp`, or `jwt.cache-max-age`.
_Avoid_: token cache, JWT cache, claims cache
