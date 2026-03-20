# Signing-Key Lifecycle

This note defines the intended lifecycle for Conclave signing keys and the publication contract that relying systems use for verification-key refresh.

## Source Of Truth

Conclave uses one configured private signing key at a time.

- the active private signing key is loaded from the PEM file referenced by `jwt.signing_private_key_file` in `server.conf.styx`
- the server derives the public key and `kid` from that configured private key
- Feldera persists public signing-key history and publication state
- relying-system JWKS publication and server-side JWT validation read the persisted public-key set rather than rebuilding history from only the current in-memory signer

This keeps private signing material local to the server while making verification-key history durable and restart-safe.

## Planned Rotation

Normal signing-key rotation is config-driven.

- operators replace the PEM file referenced by `jwt.signing_private_key_file` or repoint that config value at a new PEM file
- the server derives a new public key and `kid`
- new tokens are signed with the new key
- older public keys remain published while they are still eligible to validate active tokens

Normal rotation is expected to preserve a verification overlap window so relying systems can continue validating older unexpired tokens while new tokens start using the new signing key.

## Emergency Revocation

Emergency revocation is different from normal rotation.

- a revoked key is removed from the published verification set immediately
- if the revoked key is also the active configured signing key, token issuance stops until a new signing key is loaded
- revocation is allowed even when it leaves the server temporarily unable to sign new tokens

This is the break-glass path for suspected key compromise. The platform prefers stopping issuance over continuing to sign with a key that should no longer be trusted.

## Refresh Surfaces

Signing-key publication state uses a monotonic `jwks_generation`.

Future public contracts use that name consistently:

- `/v1/revisions` will include `jwks_generation`
- issued access tokens will carry a top-level `jwks_generation` claim

`jwks_generation` is verification-key publication metadata, not part of the token authorization snapshot. It is separate from authorization catalog and policy revisions so relying systems can refresh verification keys without conflating key publication changes with authz compilation changes.

## Reload Behavior

Focused signing-key reload should watch or reload the configured PEM file, not the old single-file startup config shape.

The intended future behavior is:

- when the configured signing-key PEM file changes, the server reloads that key material specifically
- if the derived key identity changes, the server persists the new public key state and begins signing with it
- broader runtime config should not require the same reload path just because signing-key rotation does

## Revoked-Empty JWKS Contract

An empty published verification-key set is only valid as an explicit revocation outcome.

- if all published keys have been intentionally removed by revocation, the JWKS endpoint returns `503`
- the machine-readable error code is `JWKS_REVOKED`
- if the published key set is unexpectedly empty for any other reason, the response is a generic server error rather than a revocation signal

This reserves the typed `503` contract for the specific case where relying systems should treat the empty key set as an intentional trust break rather than as an internal failure.
