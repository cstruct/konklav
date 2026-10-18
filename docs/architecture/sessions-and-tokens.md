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

## MFA, step-up and impersonation

- A credential's `mfa_factors_required` makes login stop at a partial
  session. `POST /v1/login/mfa` proves one active factor at a time. Once
  enough distinct factors are proven, the session becomes an identity
  session and gets its refresh token.
- Factors:
  - TOTP: the seed is encrypted with AES-256-GCM under configured keys,
    and replay is refused by remembering the last step.
  - Email codes: challenges.
- `amr` values: `pwd`, `otp` (TOTP), `eml` (email code or magic link),
  `sms` (phone code), `swk` (secret key).
- Step-up (`POST /v1/step-up`) proves a factor or the password again in the
  same session. It adds the method, resets `auth_time` and bumps the
  version.
- Impersonation (`POST /v1/impersonate`) needs the
  `conclave:subject:impersonate` capability. It creates a child session for
  the target with `act` naming the impersonator. The child lasts at most an
  hour and never outlives its parent: revoking a session revokes its
  children.

## Challenges and delivery

Magic links, phone codes, email MFA codes, invites and password resets are
challenges:

- single-use and short-lived
- stored as SHA-256 of the challenge id and secret
- codes allow 5 attempts
- at most 5 are sent per recipient and purpose every 10 minutes

Each one appends `delivery.requested` with the material. Only service
principals holding `conclave:delivery:read` see those events, and the
material is stripped once the challenge has expired. Start endpoints always
answer 202, so they reveal nothing about which identifiers exist.

## Response pacing

Endpoints whose timing could reveal whether an identifier exists are paced.
These are first-factor login, MFA completion, step-up, the passwordless and
password-reset start and complete pairs, password change and invite
redemption:

- A middleware starts a timer of 1.5 s ± 0.25 s (configurable under
  `pacing`) when the request arrives, and responds when both the timer and
  the handler are done.
- The handler's work runs during the wait, so the floor costs nothing when
  the work is slower. The wait holds no database connection.
- The dummy hash for unknown identifiers stays. It keeps CPU cost even, so
  paced responses don't leak through load.
- Refresh, tenant selection, sign-out and factor management are not paced:
  they need a valid session or token, which an attacker probing for
  accounts doesn't have.

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
