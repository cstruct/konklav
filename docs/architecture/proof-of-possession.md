# Proof-of-possession credentials (outline)

Status: passkeys are implemented: WebAuthn through `webauthn-rs`, with no
attestation (see `authn.passkey.*` in the authentication spec). Hardware
attestation, assertive flags, smart cards and DPoP remain an outline, not
scheduled. Federation, including national eID
schemes through OIDC brokers, is covered by
[OIDC and federation](oidc-and-federation.md). This note captures the
generic building block that covers both software and hardware keys, so that
earlier designs don't rule it out.

## Credential kind `public_key`

- **Registration:**
  1. Konklav issues a challenge.
  2. The authenticator signs it, optionally with an attestation.
  3. Konklav stores the public key, algorithm, attestation result and a
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

- The subject signs a Konklav nonce.
- On success the session gets `amr` values (`hwk` or `swk`, per RFC 8176;
  passkeys record `swk` and `mfa` until attestation can prove hardware)
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
  certificates) or through a native helper. For national eID schemes, an
  OIDC broker (see [OIDC and federation](oidc-and-federation.md)) avoids
  the question.
