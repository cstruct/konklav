# Conclave

Conclave is a standalone identity and access service. It owns subjects,
credentials, sessions, tokens, tenants, memberships, roles and policies.
Relying systems verify its tokens offline and get authorization decisions
through a small SDK that caches entitlements and keeps them fresh from a
change feed.

It is designed around:

- **clear tenancy boundaries:** a tenant tree in which a parent grants
  nothing implicitly
- **agnosticism:** actions, scope kinds, facts and session flags are catalog
  data; Conclave knows nothing about any relying system's domain
- **fast revocation without callbacks:** session and entitlement changes
  reach relying systems over SSE within about a second, and relying systems
  fall back to a central check API and fail closed when they can't keep up
- **traceability:** requirements live in Tracey-managed specs and are linked
  from code and tests

## Status

v2 has finished milestone M3, tenancy and authorization. M3 adds tenants
and memberships with facts, the action catalog, templates, roles and
assignments, entitlement compilation that matches onetwo's semantics, tenant
selection at login, session flags, and the entitlements and check APIs.
Earlier milestones built:

- subjects, and credentials in one JSON-Schema-validated table
- password and secret-key login
- server-side sessions with refresh rotation and reuse detection
- browser cookies with CSRF checks
- Ed25519 tokens with JWKS
- control-plane administration of all of the above v1, a prototype backed by Feldera, is preserved at tag `v1`.

## Repository layout

- `docs/nomenclature.md`: the shared vocabulary. Read this first.
- `docs/spec/`: normative, Tracey-managed requirements.
- `docs/architecture/`: rationale and design notes, starting with
  [`v2-overview.md`](docs/architecture/v2-overview.md).
- `items/`: software items:
  - `core`: identifiers
  - `token`: claims, JWS, JWKS
  - `authn`: hashing, refresh tokens
  - `authz`: entitlement compilation and evaluation
  - `store`: Postgres, migrations, repositories
  - `server`: the binary
  - `test-support`: shared test helpers
- `config/`: development configuration.
- `dev/`: local services for development.
- `.agents/`: agent skills and the planning standard.

## Development environment

[mise](https://mise.jdx.dev) manages the toolchain, the environment and the
local services. It covers Rust, Tracey and Diesel's CLI (which bundles libpq,
so no system Postgres client is needed).

```sh
mise trust && mise install
mise run db:up      # Postgres 18 with pg_jsonschema in Docker on localhost:55432
```

mise sets `DATABASE_URL`, `CONCLAVE_CONFIG` and `CONCLAVE_SECRETS` for the
local setup. Everyday tasks:

- `mise run serve` starts Postgres, migrates it and serves on ports 8080 to
  8082.
- `mise run test` runs every test, each database test in its own database.
- `mise run lint` checks formatting, clippy (warnings are errors) and Tracey
  validation.
- `mise run migrate` applies migrations; `mise run db:schema` regenerates the
  Diesel schema.

Other database tasks:

- `db:down` stops Postgres and keeps its data.
- `db:reset` stops it and deletes the data.
- `db:status` shows its status.
- `db:logs` follows its logs.
- `db:psql` opens psql inside the container.

To use another port, set `CONCLAVE_DEV_PG_PORT`, for example in an untracked
`mise.local.toml`.

## Stack

- Rust, axum, tokio
- PostgreSQL via Diesel (`diesel-async`, embedded forward-only migrations)
- `ordna` for layered configuration with separate secrets
- Ed25519 JWTs published through JWKS
- pyo3 for the Python relying binding
