# konklav-token

Library crate for Konklav access tokens: the claims, compact EdDSA (Ed25519) JWS signing and verification, key ids, and JWKS documents.

## Responsibilities

- `AccessClaims`, `TokenKind` and `Actor`: the token payload contract shared by the issuer and verifiers.
- `Signer`: signs claims with one Ed25519 key, and sets `kid` in the header.
- `verify`: checks algorithm, signature, issuer, audience, expiry and issue time.
- `kid_for`, `Jwk`, `JwkSet`: key ids and JWKS documents.

It performs no I/O and reads no clock: callers pass the current time. That lets the relying core (M4) reuse it unchanged.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-core` | Identifier types in the claims |
| `konklav-server` | Issues tokens and serves JWKS |
| `konklav-relying` (planned) | Verifies tokens in relying systems |

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p konklav-token
```

- Direct coverage: sign and verify round-trips, unknown keys, forged signatures, tampered payloads, other algorithms, time, issuer and audience checks, and kid derivation.
- Indirect coverage: the server's end-to-end auth tests verify issued tokens against the published JWKS.

## Traceability and related docs

- [Tokens and claims spec](../../docs/spec/tokens-and-claims.md) and [item spec](../../docs/spec/software-items/token.md)
- [Sessions and tokens](../../docs/architecture/sessions-and-tokens.md)
- [Nomenclature](../../docs/nomenclature.md)
