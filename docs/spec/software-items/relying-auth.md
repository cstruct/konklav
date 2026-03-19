# Relying Auth Software Item

This file defines stable implementation-contract requirements owned by `conclave-relying-auth`.

## JWT and offline evaluation boundary

r[item.relying-auth.ed25519-jwt-boundary]
The `conclave-relying-auth` crate MUST provide signing, verification, and JWKS publication for Conclave-issued access tokens using Ed25519-compatible key material suitable for relying-system distribution.

r[item.relying-auth.validation-options]
The `conclave-relying-auth` crate MUST allow callers to validate Conclave-issued tokens against issuer, audience, tenant context, current catalog revision, current policy revision, and optional action or scope expectations.

r[item.relying-auth.offline-decision-evaluation]
The `conclave-relying-auth` crate MUST be able to evaluate token-carried authorization snapshots against action-catalog metadata and optional scope context without requiring a synchronous control-plane callback.
