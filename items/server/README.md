# konklav-server

The Konklav server binary. It serves the subject-facing, relying and control-plane surfaces from one process.

## Responsibilities

- Loading runtime configuration with ordna, in this order:
  1. a Styx config file
  2. a Styx secrets file
  3. `KONKLAV__*` environment variables

  Secret values are only accepted from the secrets file, and every problem is reported at once.
- Configuration is split into ordna contexts (`ListenConfig`, `DatabaseConfig`, `LogConfig`), and each command loads only the ones it needs:
  - `serve` and `check-config` load all three.
  - `migrate` loads only the database and log contexts, so it runs without any `listen` settings.
  - `bootstrap` loads the database, log and MFA contexts.

  Keys belonging to contexts a command doesn't load are still validated, so typos are still caught.
- Binding one listener per distinct surface address. Surfaces configured with the same address share a listener.
- Sweeping (`sweeper.rs`): every `retention.sweep_interval_seconds` (default 300), one instance at a time deletes what retention allows, in batches of `retention.batch_size`:
  - expired challenges once the one-day send-limit window has passed
  - login attempts older than the one-day rate-limit window
  - expired client- and bearer-assertion `jti`s
  - sessions `retention.sessions_days` (default 30) after they ended
  - events older than `feed.retention_hours`
  - row versions `history.retention_days` (default 90) after they stopped being current, when history is enabled

  It also erases the challenge material from stored `delivery.requested` events once their challenge has expired.
- Telemetry (`telemetry.rs`), configured under `telemetry`:
  - logs to stderr as text or JSON (`logs.format json`, with trace and span ids)
  - traces, metrics and logs exported over OTLP (HTTP or gRPC) when `traces.enabled`, `metrics.enabled` or `logs.export` is set
  - every request is a server span named by method and route template, continuing a caller's `traceparent`
  - requests to identity providers, their keys, peers and back-channel logout endpoints are client spans that carry the trace
  - metrics:
    - request durations (`http.server.request.duration`) by route, status and error code
    - refusals for load
    - hashing wait and busy slots
    - access tokens issued
    - open feed streams
    - logout deliveries
    - rows swept
    - pool connections
    - outbound requests

  Telemetry never records login identifiers, secrets, tokens, codes, client addresses or request paths. Export headers, such as an API key, belong in the secrets file under `telemetry.otlp.headers`.
- Working out each client's address from the connection, or from `X-Forwarded-For` when the connection comes from one of `listen.trusted_proxies`, for per-address rate limits.
- Liveness (`/healthz`) and readiness (`/readyz`: database reachable and no pending migrations) on every listener.
- The typed error model: `{"error": {"code": "SCREAMING_SNAKE_CASE", "message": "..."}}`, including for unknown endpoints and methods.
- Graceful shutdown on Ctrl-C and SIGTERM.
- Subject-facing surface (`/v1`):
  - `login/password` and `login/secret-key`, rate limited per identifier, with failures that reveal nothing
  - `refresh`, with rotation and reuse detection
  - `sign-out` and `sign-out/others`
  - browser clients get the refresh token as an `HttpOnly` cookie and must pass Origin and `X-Konklav-Client` checks
- Subject-facing `login/tenant` moves a session into a tenant where the subject has an active membership. The new token carries `tid`, `mid` and portable facts. Logins may request restrictive session flags that the catalog marks as requestable.
- `GET /v1/capabilities`: the `konklav:` capabilities the caller holds, for operator tools such as the console.
- Passkeys (`src/passkeys.rs` wraps `webauthn-rs`; routes in `src/passkeys_api.rs`):
  - registering from a recently authenticated full session (`passkeys/registration/options`, then `passkeys/registration`)
  - usernameless login (`login/passkey/options`, then `login/passkey`), recording `swk` and `mfa`
  - step-up (`step-up/passkey/options`, then `POST /v1/step-up` with `ceremony` and `passkey`)
  - listing and removing the caller's own passkeys (`GET /v1/passkeys`, `DELETE /v1/passkeys/{id}`)

  Each ceremony's `webauthn-rs` state lives in a single-use challenge until the second call; the stored key is versioned opaque JSON in the credential's data.
- MFA (TOTP and email-code factors; partial sessions can list their active factors, and browsers get their cookie when MFA completes), step-up, magic-link and phone-code login, password reset and change, invite redemption, and impersonation. These emit `delivery.requested` for anything a relying system must send.
- Relying surface, for service principals only:
  - `/.well-known/jwks.json`
  - `/v1/entitlements/{subject}[/{tenant}]`
  - `/v1/check`, which decides from current state, session validity included
- Control-plane surface (`/v1`):
  - subjects (idempotent `PUT`, disable and enable)
  - credentials (create, revoke, replace a password, rotate a secret-key slot). A password credential can be created from an Argon2id `password_hash` made elsewhere instead of a `password`.
  - sessions (list, get, revoke by filter)
  - signing keys (list, break-glass revoke)
  - the catalog
  - tenants (create with roles instantiated from templates; facts; state, where leaving `active` ends the tenant's sessions)
  - memberships (create, facts, end, assignments)
  - templates and roles, where roles of `root` are global roles
  - global assignments
  - invites (`POST /v1/invites`)
  - an operator view of a subject's entitlements, with explanations (`/v1/subjects/{id}/explain`)
  - decision explanations (`POST /v1/subjects/{id}/explain-decision`), now or, with `history.enabled`, as of a past time (`at`, RFC 3339) within the history horizon
  - listings of subjects (by kind or login identifier), tenants (by parent) and a tenant's memberships

  Each area requires a `konklav:` capability, held through a global role (`konklav:control:all` covers everything). Two built-in global roles ship with every instance and can be assigned but not changed: `konklav.admin` (`konklav:control:all`) and `konklav.delivery` (`konklav:delivery:read`). Role keys starting with `konklav.` are reserved for them. An optional bootstrap token from the secrets file is also accepted. Use it to create the first operator (a human subject with a password credential and the `konklav.admin` global role), then remove it.

## Public interface

- CLI: `konklav-server --config <file> --secrets <file> <serve|migrate|check-config|bootstrap>`.
  - The file paths can also come from `KONKLAV_CONFIG` and `KONKLAV_SECRETS`.
- Configuration: the contexts in `src/config.rs`:
  - `listen`, `database`, `log`
  - `tokens`: issuer, audience, lifetimes and signing-key PEM files
  - `history`: `enabled` (default off) and `retention_days` (default 90). Applied at startup, so every instance on a database must agree; turning it off discards what was recorded
  - `browser`: allowed origins, cookie security, and the `passkeys` section (relying party ID and name, origins)
  - `control`: the bootstrap token (secret) The development config is in `config/dev.styx` and `config/dev.secrets.styx`.
- HTTP: health endpoints at the root; versioned endpoints under `/v1`. Each surface's routes are in `src/surface.rs`.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-store` | Pool, migrations, readiness checks and every repository |
| `konklav-authn` | Password and secret hashing, refresh tokens |
| `konklav-token` | Signing access tokens, JWKS |
| `konklav-authz` | Compiling entitlement sets and evaluating checks |
| `webauthn-rs` | Passkey ceremonies. It links OpenSSL, so it stays in this crate: `konklav-authn` is a dependency of relying systems |
| `konklav-test-support` | Isolated databases in tests |
| PostgreSQL | Must be reachable for readiness and for every stateful endpoint |

## Running

```sh
mise run serve
```

This starts Postgres, creates an untracked dev signing key if needed, applies migrations, and serves on `127.0.0.1:8080` (subject), `:8081` (relying) and `:8082` (control).

### Bootstrapping data

`bootstrap` applies a bootstrap set to the database directly: tenants, people, credentials and grants, from CSV tables, Styx documents and a `catalog.json`, or directories of them. The formats are described in [`konklav-bootstrap`](../bootstrap/README.md).

```sh
cargo run -p konklav-server -- bootstrap --dry-run examples/bootstrap/nested/seed.styx
cargo run -p konklav-server -- bootstrap examples/bootstrap/nested/seed.styx
```

- **One transaction.** Every record is written in a savepoint of its own. The run reports each problem and conflict with its file and line, and commits only when there are none.
- **Re-runnable.**
  - Records that exist with the same content are skipped, so a set can be applied again.
  - A record that exists with different content is a conflict.
  - Nothing the set doesn't name is changed.
- **`--dry-run`** does everything but commit, and prints what would be created, skipped, updated or in conflict.
- **Passwords** must arrive as Argon2 hashes. `--allow-plaintext-passwords` accepts plaintext for development seeds and hashes it.
- **Requirements:** it refuses to run while migrations are pending, and needs the `mfa` keys to import TOTP seeds.
- **Exit codes:** 0 when the set applied or the dry run found nothing wrong, 1 for problems, 2 for conflicts.

## Testing

```sh
mise run test
```

- Direct coverage:
  - config layering, secrets placement and error reporting
  - liveness, readiness (ready, database down, migrations pending) and typed errors, through the router
  - binding and graceful shutdown of the listeners
  - end-to-end auth flows through the router:
    - login, refresh, reuse detection, sign-out
    - browser cookies and CSRF checks
    - secret-key slots
    - credential replacement, subject disabling, MFA-required partial tokens
    - session administration, signing-key revocation
    - passkey registration, login, step-up and removal, with a software authenticator (`tests/passkeys.rs`)
  - the runnable examples in `examples/`, against this build's binary (`tests/examples.rs`)
  - telemetry: spans, metrics and logs exported to a fake OTLP collector, trace propagation in and out, and nothing identifying in what's exported (`tests/telemetry.rs`)
  - retention: what the sweeper deletes and keeps, and its lock (`tests/retention.rs`)
  - history: decisions explained as of a past time, the history horizon, disabling, and sweeping old row versions (`tests/history.rs`)
  - the bootstrap command, applying both example sets, re-runs, dry runs, conflicts and located problems (`tests/bootstrap.rs`)
- Indirect coverage: none yet.

## Behavior notes

- Surfaces on port `0` always get a listener of their own, because the OS picks a distinct port for each.
- Key files in `tokens` are resolved relative to the working directory.
- Building needs OpenSSL headers (for example `brew install openssl@3`), for `webauthn-rs`.
- `serve` doesn't apply migrations. It warns about pending ones, and readiness fails until `migrate` runs.

## Traceability and related docs

- [Platform spec](../../docs/spec/platform.md)
- [overview](../../docs/architecture/overview.md)
- [Traceability guidance](../../docs/traceability-guidance.md)
- [Nomenclature](../../docs/nomenclature.md)
