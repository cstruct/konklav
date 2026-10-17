# conclave-server

The Conclave server binary. It serves the subject-facing, relying and control-plane surfaces from one process.

## Responsibilities

- Loading runtime configuration with ordna, in this order:
  1. a Styx config file
  2. a Styx secrets file
  3. `CONCLAVE__*` environment variables

  Secret values are only accepted from the secrets file, and every problem is reported at once.
- Configuration is split into ordna contexts (`ListenConfig`, `DatabaseConfig`, `LogConfig`), and each command loads only the ones it needs:
  - `serve` and `check-config` load all three.
  - `migrate` loads only the database and log contexts, so it runs without any `listen` settings.

  Keys belonging to contexts a command doesn't load are still validated, so typos are still caught.
- Binding one listener per distinct surface address. Surfaces configured with the same address share a listener.
- Liveness (`/healthz`) and readiness (`/readyz`: database reachable and no pending migrations) on every listener.
- The typed error model: `{"error": {"code": "SCREAMING_SNAKE_CASE", "message": "..."}}`, including for unknown endpoints and methods.
- Graceful shutdown on Ctrl-C and SIGTERM.
- Subject-facing surface (`/v1`):
  - `login/password` and `login/secret-key`, rate limited per identifier, with failures that reveal nothing
  - `refresh`, with rotation and reuse detection
  - `sign-out` and `sign-out/others`
  - browser clients get the refresh token as an `HttpOnly` cookie and must pass Origin and `X-Conclave-Client` checks
- Relying surface: `/.well-known/jwks.json`.
- Control-plane surface (`/v1`):
  - subjects (idempotent `PUT`, disable and enable)
  - credentials (create, revoke, replace a password, rotate a secret-key slot)
  - sessions (list, get, revoke by filter)
  - signing keys (list, break-glass revoke)

  Until operator authorization arrives in M6, the control plane is guarded by one bootstrap bearer token from the secrets file.

## Public interface

- CLI: `conclave-server --config <file> --secrets <file> <serve|migrate|check-config>`.
  - The file paths can also come from `CONCLAVE_CONFIG` and `CONCLAVE_SECRETS`.
- Configuration: the contexts in `src/config.rs`:
  - `listen`, `database`, `log`
  - `tokens`: issuer, audience, lifetimes and signing-key PEM files
  - `browser`: allowed origins, cookie security
  - `control`: the bootstrap token (secret) The development config is in `config/dev.styx` and `config/dev.secrets.styx`.
- HTTP: health endpoints at the root; versioned endpoints under `/v1`. Each surface's routes are in `src/surface.rs`.

## Relationships

| Software item | Relationship |
|---|---|
| `conclave-store` | Pool, migrations, readiness checks and every repository |
| `conclave-authn` | Password and secret hashing, refresh tokens |
| `conclave-token` | Signing access tokens, JWKS |
| `conclave-test-support` | Isolated databases in tests |
| PostgreSQL | Must be reachable for readiness and for every stateful endpoint |

## Running

```sh
mise run serve
```

This starts Postgres, creates an untracked dev signing key if needed, applies migrations, and serves on `127.0.0.1:8080` (subject), `:8081` (relying) and `:8082` (control).

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
- Indirect coverage: none yet.

## Behavior notes

- Surfaces on port `0` always get a listener of their own, because the OS picks a distinct port for each.
- Key files in `tokens` are resolved relative to the working directory.
- `serve` doesn't apply migrations. It warns about pending ones, and readiness fails until `migrate` runs.

## Traceability and related docs

- [Platform spec](../../docs/spec/platform.md)
- [v2 overview](../../docs/architecture/v2-overview.md)
- [Traceability guidance](../../docs/traceability-guidance.md)
- [Nomenclature](../../docs/nomenclature.md)
