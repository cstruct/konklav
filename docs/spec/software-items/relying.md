# Relying Core Software Item

Stable implementation contracts owned by `konklav-relying`, the relying
core.

r[item.relying.sans-io]
`konklav-relying` MUST NOT perform network I/O, read clocks, spawn tasks or
sleep. The host binding supplies the current time, JWKS documents,
entitlement responses, feed events and check-API responses.

r[item.relying.scheduler]
`konklav-relying` MUST expose its pending work (fetches to perform and the
earliest time each is due) so that host bindings can run them and feed the
results back.

r[item.relying.portable]
`konklav-relying` MUST compile for native targets and for `wasm32`, with no
platform-specific dependencies in its default feature set.

r[item.relying.request-descriptor]
The verification API of `konklav-relying` MUST accept an optional request
descriptor (method and URL) so that sender-constrained tokens can be
verified later without breaking the API.

r[item.relying.raw-headers]
The verification API of `konklav-relying` MUST take the request's raw
`Authorization` and `DPoP` header values, so host bindings never parse
authorization schemes or proofs themselves.

r[item.relying.single-implementation]
Host bindings MUST NOT re-implement verification, evaluation or cache-state
logic. They only translate between the core and their language's runtime.
