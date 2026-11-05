# Proof-of-possession credentials (outline)

Status: passkeys are implemented: WebAuthn through `webauthn-rs`, with no
attestation (see `authn.passkey.*` in the authentication spec). DPoP is specified
but not built (see below). Hardware attestation, assertive flags and smart
cards remain an outline, not scheduled. Federation, including national eID
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

## Sender-constrained tokens (DPoP)

Status: specified (`token.dpop.*`, `oidc.provider.dpop.*`,
`relying.verify.dpop*`), not built.

DPoP (RFC 9449) makes a stolen access or refresh token useless without the
client's key. That matters most for browser apps registered as public OIDC
clients: they hold their tokens in JavaScript, so an XSS bug can take them,
but a non-extractable WebCrypto key can't be exported. An attacker can then
act only while the page is open, as with an `HttpOnly` cookie.

How it works:

1. **Binding.** The client sends a DPoP proof with its token request. The
   session that grant starts becomes a *bound session*: it stores the key
   thumbprint (`jkt`). Binding happens only at creation
   (`r[token.dpop.binding]`). Letting a later refresh add a binding would
   let whoever holds a stolen unbound refresh token bind the session to
   *their* key.
2. **Access tokens** carry `cnf.jkt`. Konklav's own access tokens use the
   same claims type (`r[item.token.shared-claims]`), so `cnf` is an
   optional field on `AccessClaims`. A relying SDK older than DPoP support
   ignores the unknown claim, so it accepts such a token as a bearer
   token. That is no weaker than today, but relying systems must upgrade
   before the protection holds for them.
3. **Refresh tokens** of a bound session are accepted only with a proof
   from the same key (`r[token.refresh.dpop-bound]`). The proof is checked
   *before* rotation. Otherwise a thief without the key could still rotate
   the token, and the real client's next refresh would look like reuse and
   revoke the session. A refused refresh leaves the session as it was.
   Presenting an already-rotated refresh token still revokes the session
   (`r[session.refresh.rotation]`).
4. **Resource requests** use `Authorization: DPoP <token>` plus a fresh
   proof with `ath`. A token with `cnf` sent as `Bearer` is refused
   (`r[token.dpop.scheme]`), so dropping the proof gains an attacker
   nothing.

Where proofs are checked:

- **One implementation.** `konklav-token` verifies proofs and computes
  thumbprints (`r[item.token.dpop-proof]`). It already builds for `wasm32`
  and the relying core uses it. ES256 uses the `p256` crate, which is
  already a workspace dependency. EdDSA reuses `ed25519-dalek`.
- **Konklav** (token and UserInfo endpoints) compares `htu` with the URLs
  in its discovery document, not the `Host` header
  (`r[oidc.provider.dpop.htu]`). It keeps used `jti`s in a table like
  `client_assertion`, which the sweeper prunes.
- **The relying core** gets the raw `Authorization` and `DPoP` headers and
  the request descriptor (`r[item.relying.raw-headers]`). The host binding
  must pass the URL the *client* addressed. Behind a reverse proxy, that
  means the public URL, not the upstream one. The core keeps accepted
  `jti`s in a bounded in-memory set for the freshness window. Replays across
  separate relying-system instances aren't caught. Each proof is already
  limited to one method, one URL, one token and about a minute.
- **The check API** never sees proofs. The relying SDK verifies the proof
  first, against the token's `cnf.jkt` read without verification, and the
  check API then verifies the token's signature. A forged `cnf` therefore
  fails at Konklav (`r[relying.verify.dpop-before-check]`).

Out of scope for the first slice:

- Server-provided nonces (`DPoP-Nonce`, `use_dpop_nonce`). They remove the
  dependence on client clocks, but cost an extra round trip. CORS already
  exposes `dpop-nonce`, so they can be added later.
- Binding Konklav's own `/v1` native sessions (password, OTP and passkey
  logins that return a refresh token in the body). Browser sessions don't
  need it: their refresh token is already an `HttpOnly` cookie.
- Requiring a proof at revocation. RFC 9449 doesn't, and the worst a thief
  can do there is end the session.

## Open points

- Account recovery when the only credential is a lost hardware key.
- Trust-store management beyond static configuration.
- Whether smart-card login runs through a browser (WebAuthn or TLS client
  certificates) or through a native helper. For national eID schemes, an
  OIDC broker (see [OIDC and federation](oidc-and-federation.md)) avoids
  the question.
