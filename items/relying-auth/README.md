# Relying Auth

`conclave-relying-auth` is the Rust crate that lets relying systems work with Conclave-issued JWTs and token-carried authorization snapshots.

It defines the claims model, signs tokens for server-side issuance paths, publishes JWKS data, and verifies tokens against issuer, audience, tenant, revision, action, and scope expectations.

## Responsibilities

- Define the shared JWT claims and authorization-snapshot structures used across Conclave token flows.
- Sign Conclave access tokens and derive a matching verifier from the active signing key.
- Publish Ed25519 JWKS data for relying-system verification.
- Verify tokens against key material, issuer, audience, tenant, revision, and optional action/scope checks.
- Evaluate token-carried authorization bits for offline relying-system decisions.

Out of scope:

- serving HTTP endpoints directly
- issuing sessions or invites
- owning the full control-plane runtime

## Public Interface

Primary entry point:

- `src/lib.rs`
  - Defines the JWT claims model, JWKS types, signing utilities, verification utilities, and access-decision output types.

Interface overview:

- Claims and authorization snapshot types
  - `AccessTokenClaims`
  - `AuthorizationSnapshotClaim`
  - `ScopedBitsClaim`
  - `ActorChainClaim`
- Catalog and validation output
  - `ActionCatalogEntry`
  - `ValidatedToken`
  - `AccessDecision`
  - `ValidationOptions`
- Signing and verification
  - `JwtSigner`
  - `JwtVerifier`
  - `Jwk`
  - `JwkSet`

See [`src/lib.rs`](src/lib.rs) for the public API.

## Relationships

### Dependency Summary

| Software item | Relationship |
| --- | --- |
| `conclave-core` | Provides shared IDs, action names, and revision aliases used in claims and verification types. |

### Dependent Summary

| Software item | Relationship |
| --- | --- |
| `conclave-controlplane-api` | Reuses token-claim and action-catalog entry types in API DTOs. |
| `conclave-server` | Uses the signer, verifier, and JWKS types for token issuance and relying-system responses. |
| External relying systems | Depend on the JWT and JWKS shapes defined here when validating Conclave-issued tokens offline. |

## Usage

Use `JwtSigner` and `JwtVerifier` when Conclave or another Rust consumer needs to sign or verify Conclave-issued tokens.

```rust
use conclave_relying_auth::{JwtSigner, ValidationOptions};

let signer = JwtSigner::from_seed([7; 32]);
let verifier = signer.verifier();
let _options = ValidationOptions::default();
```

## Running

This software item is a library crate and is not run directly as its own process.

It is exercised through other software items:

- `conclave-server`
  - uses it for token issuance, validation, and JWKS publication
- `conclave-controlplane-api`
  - reuses token claims and catalog-entry types in API responses
- tests in this crate and in downstream crates

## Testing

Run this software item's crate-local tests with:

```sh
cargo test -p conclave-relying-auth
```

Coverage shape:

- Direct coverage
  - This crate's direct tests cover Ed25519 token signing and verification, including scope-aware authorization decisions.
- Indirect coverage
  - `conclave-server` exercises these types in login, assumption, token validation, and JWKS publication flows.
  - `conclave-controlplane-api` reuses the token and catalog types at the transport boundary.

## Behavior Notes

- Verification can optionally enforce issuer, audience, tenant, catalog revision, policy revision, action, scope kind, and scope id expectations.
- Offline authorization decisions are driven by token-carried bitsets rather than a round-trip to the control plane.
- The signer can derive a matching verifier directly from its active key material, which is convenient for server-local issuance flows and tests.

## Traceability And Related Docs

- [Authentication and authorization spec](../../docs/spec/authn-and-authz.md)
- [Tokens and claims spec](../../docs/spec/tokens-and-claims.md)
- [Platform spec](../../docs/spec/platform.md)
- [Repository traceability guidance](../../docs/traceability-guidance.md)
- [Software-item README guidance](../../docs/software-item-readmes.md)
- [Project nomenclature](../../docs/nomenclature.md)
