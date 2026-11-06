# Token Software Item

Stable implementation contracts owned by `konklav-token`, which defines
access-token claims, signs and verifies them, and builds JWKS documents.

r[item.token.sans-io]
`konklav-token` MUST NOT perform I/O or read clocks. Callers pass the current
time and the verification keys in.

r[item.token.portable]
`konklav-token` MUST compile for native targets and for `wasm32`, with no
platform-specific dependencies in its default feature set, so that the
relying core can depend on it.

r[item.token.shared-claims]
`AccessClaims` and `verify` in `konklav-token` MUST be the only definition of
the access-token payload and the only access-token verification. The issuer
and every verifier use them, so that a token Konklav issues is read the same
way wherever it is verified.

r[item.token.dpop-proof]
`konklav-token` MUST hold the only DPoP proof verification and key
thumbprint computation. Konklav's endpoints and the relying core both use
them, and the caller supplies the current time, the request and any replay
state.
