# konklav-token

Library crate for Konklav access tokens: the claims, compact EdDSA (Ed25519) JWS signing and verification, key ids, JWKS documents, and DPoP proof verification.

## Responsibilities

- `AccessClaims`, `TokenKind`, `Actor` and `Confirmation` (`cnf.jkt`): the token payload contract shared by the issuer and verifiers.
- `Signer`: signs claims with one Ed25519 key, and sets `kid` in the header.
- `verify`: checks algorithm, signature, issuer, audience, expiry and issue time.
- `kid_for`, `Jwk`, `JwkSet`: key ids and JWKS documents.
- `verify_proof`: the only DPoP (RFC 9449) proof verification, used by the server and the relying core:
  - `typ`, `ES256` or `EdDSA` with a matching public key, and the signature
  - method and normalized URL, freshness, and the access token's hash and key
  - callers keep the replay state, from the `jkt` and `jti` it returns
- `ec_thumbprint`, `ed25519_thumbprint`, `access_token_hash`, `normalize_htu`: RFC 7638 key thumbprints, `ath` and URL normalization.
- With the optional `openapi` feature, `TokenKind` describes itself as an OpenAPI schema, for the control plane's API document.

It performs no I/O and reads no clock: callers pass the current time. That lets the relying core (M4) reuse it unchanged.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-core` | Identifier types in the claims |
| `konklav-server` | Issues tokens and serves JWKS |
| `konklav-relying` | Verifies tokens and DPoP proofs in relying systems |

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p konklav-token
```

- Direct coverage: sign and verify round-trips, unknown keys, forged signatures, tampered payloads, other algorithms, time, issuer and audience checks, and kid derivation. DPoP: each refusal of `verify_proof`, ES256 and Ed25519 proofs, URL normalization, and the RFC 9449 thumbprint vector.
- Indirect coverage: the server's end-to-end auth tests verify issued tokens against the published JWKS.

## Traceability and related docs

- [Tokens and claims spec](../../docs/spec/tokens-and-claims.md) and [item spec](../../docs/spec/software-items/token.md)
- [Sessions and tokens](../../docs/architecture/sessions-and-tokens.md)
- [Nomenclature](../../docs/nomenclature.md)
