# Sessions and tokens

## Login stages

```
credential ──▶ partial ──MFA──▶ identity ──select tenant──▶ tenant
   (pwd/otp/link/secret key)        │                        │
                                    └─── switch tenant ◀─────┘ (sv+1)
```

Every stage transition updates one session record and increases its
version. Tokens from earlier stages stop working for anything except the
next step, because their token kind is not accepted elsewhere.

## Session record

`session { id, subject, credential, tenant?, membership?, amr[], auth_time,
flags[], facts_snapshot, version, refresh_hash, refresh_family,
impersonator?, expires_at, revoked_at?, revoked_reason? }`

- Refresh rotation:
  1. Compare and swap on `refresh_hash`.
  2. If the presented token matches an older value in the same family,
     revoke the session (reuse detection).
- Revocation sets `revoked_at` and bumps `version` in one statement, then
  emits `session.changed`.

## Session flags

Flags are catalog-declared labels that Conclave copies into `sfl` without
interpreting them.

- **Restrictive** flags (for example, a session limited to a subject's
  personal tenant) deny by default. A relying operation must admit the flag
  explicitly.
- **Assertive** flags (for example `device_bound`) are positive claims that
  an operation can require.

A flag is set only by:

- catalog rules attached to a credential kind or login endpoint
- an explicit login request parameter that the catalog permits
- a step-up flow that the catalog permits (for example, a hardware-key
  proof sets `device_bound`)

Relying systems never set or clear flags on existing sessions.

## Browser clients

- The refresh token is a cookie with these attributes:
  - `HttpOnly; Secure; SameSite=Strict`
  - `Path=/v1/refresh`, plus a second cookie path for `/v1/sign-out`
  - scoped to Conclave's host
- The access token is returned in the body and kept in memory by the
  frontend. A reload calls `/v1/refresh` to get a new one.
- `SameSite=Strict` requires the frontend and Conclave to share a
  registrable domain (for example `app.example` and `auth.example`).
- CSRF defence in depth: an `Origin` allow-list plus a required custom
  header (for example `X-Conclave-Client: web`), which forces a CORS
  preflight.
- Non-browser clients use body tokens. The login endpoint variant or an
  explicit `client=browser|native` parameter chooses between the two.

## Signing keys

- Private keys come from secret files; at most one is active for signing at
  a time.
- Public-key history is stored in Postgres with
  `published_at, activated_at, retired_at, revoked_at`.
- Rotation:
  1. Load and publish the new key.
  2. Activate it once relying JWKS caches have had time to refresh
     (`signing_keys.changed` speeds this up).
  3. Retire the old key and keep it published until `retired_at` + maximum
     token TTL.
- Break-glass: mark the key revoked and remove it from JWKS immediately.
  Issuance fails with `SIGNING_KEY_UNAVAILABLE` until another key is
  active.
