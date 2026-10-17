# Proof-of-possession credentials (outline)

Status: outline only, not scheduled. Federation (OIDC, SAML, national eID
schemes) is out of scope for now. This note captures the generic building
block that covers both software and hardware keys, so that earlier designs
don't rule it out.

## Credential kind `public_key`

- **Registration:**
  1. Conclave issues a challenge.
  2. The authenticator signs it, optionally with an attestation.
  3. Conclave stores the public key, algorithm, attestation result and a
     signature counter where the authenticator has one.
- **Software keys:** platform keystores (Secure Enclave, Android Keystore,
  TPM-backed OS keys) and passkeys.
- **Hardware keys:** FIDO2 authenticators, and smart cards carrying X.509
  keys.

## Attestation

Attestation is pluggable by format:

| Format | Verification |
|---|---|
| WebAuthn `packed`, `tpm`, `apple`, `android-key` | Per the WebAuthn spec, against configured trust roots |
| X.509 | Chain to configured trust anchors, with revocation checking (OCSP/CRL) as configured |
| `none` | No hardware claim |

The result becomes credential facts such as `hardware_backed=true` or
`attestation_format=packed`.

## Authentication

- The subject signs a Conclave nonce.
- On success the session gets `amr` values (`hwk` or `swk`, per RFC 8176)
  and, if the catalog says so, assertive flags such as `device_bound`.
- Relying operations can then require these through ordinary step-up
  requirements and flag requirements. No new decision concept is needed.

## Sender-constrained tokens (optional, per session)

- DPoP (RFC 9449): access tokens carry `cnf.jkt`, and every request carries
  a DPoP proof.
- The relying core verifies the proof against the request method and URL.
  The core's verify API already takes an optional request descriptor
  (`r[item.relying.request-descriptor]`), so this is additive.
- Refresh tokens for DPoP sessions are bound to the same key.

## Open points

- Account recovery when the only credential is a lost hardware key.
- Trust-store management beyond static configuration.
- Whether smart-card login runs through a browser (WebAuthn or TLS client
  certificates) or through a native helper. This matters for national eID
  schemes and is therefore deferred together with federation.
