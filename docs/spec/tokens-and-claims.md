# Tokens And Claims

Access tokens, refresh tokens and signing keys.

## Access tokens

r[token.access.jwt]
Access tokens MUST be JWTs signed with EdDSA over Ed25519.

r[token.access.standard-claims]
Access tokens MUST carry `iss`, `sub`, `aud`, `jti`, `iat` and `exp`.

r[token.access.session-claims]
Access tokens MUST carry the session id (`sid`), the session version they
were issued at (`sv`), the authentication methods (`amr`) and the
authentication time (`auth_time`).

r[token.access.kind]
Access tokens MUST carry a token kind matching the login stage (`partial`,
`identity`, `tenant`) or a single-purpose kind (`reset_password`, `invite`).
Relying systems MUST accept only kinds an operation explicitly allows.

r[token.access.tenant-claims]
Tenant-stage access tokens MUST carry the target tenant (`tid`) and the
membership (`mid`).

r[token.access.actor-chain]
Tokens issued for impersonation or assumption MUST carry the originating
subject and tenant in a structured `act` claim.

r[token.access.flags]
Access tokens MUST carry the session's flags in `sfl`.

r[token.access.facts]
Access tokens MAY carry portable facts in `fct`, within the configured size
limit. They MUST NOT carry non-portable facts.

r[token.access.no-grants]
Access tokens MUST NOT carry entitlements, role definitions or policy
source. Relying systems get grants from entitlement sets.

r[token.access.ttl]
Access token lifetime MUST be bounded by a configured maximum.

## Refresh tokens

r[token.refresh.opaque]
Refresh tokens MUST be opaque, high-entropy values stored only as hashes,
each bound to one session.

## Signing keys

r[token.keys.kid]
Every signing key MUST have a `kid` derived deterministically from its
public key (base64url of the SHA-256 of the raw public key).

r[token.keys.jwks]
Conclave MUST publish all verification keys that can still validate
unexpired tokens at `/.well-known/jwks.json`.

r[token.keys.rotation-overlap]
Planned key rotation MUST publish the new key before using it to sign, and
MUST keep the old key published until every token it signed has expired.

r[token.keys.break-glass]
An operator MUST be able to revoke a key immediately. A revoked key MUST be
removed from JWKS, and issuance MUST stop if no other key is usable.

r[token.keys.event]
Every change to the set of published keys MUST emit a
`signing_keys.changed` event.

r[token.keys.private-material]
Private signing keys MUST come from secret configuration. Conclave MUST NOT
persist private key material in its database.

## Illustrative payload

```json
{
  "iss": "https://auth.example",
  "aud": "api",
  "sub": "0193a2f1-5f0e-7c4e-9a43-0b6e9d1c2a10",
  "jti": "0193a2f1-6b21-7d02-8c1f-4e0a5b9c7d33",
  "iat": 1792224000,
  "exp": 1792224900,
  "knd": "tenant",
  "sid": "0193a2f1-6a00-7a11-b2c4-1d2e3f4a5b6c",
  "sv": 7,
  "amr": ["pwd", "otp"],
  "auth_time": 1792223950,
  "tid": "0193a2f0-0000-7000-8000-000000000001",
  "mid": "0193a2f0-1111-7000-8000-000000000002",
  "sfl": ["restricted_personal"],
  "fct": { "tenant_type": "personal" },
  "act": { "sub": "0193a2ef-aaaa-7000-8000-000000000003", "tid": "root" }
}
```
