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

v2 is at milestone M0: specification and architecture. v1, a prototype
backed by Feldera, is preserved at tag `v1`.

## Repository layout

- `docs/nomenclature.md`: the shared vocabulary. Read this first.
- `docs/spec/`: normative, Tracey-managed requirements.
- `docs/architecture/`: rationale and design notes, starting with
  [`v2-overview.md`](docs/architecture/v2-overview.md).
- `items/`: software items (Rust crates and bindings), added from M1.
- `.agents/`: agent skills and the planning standard.

## Development environment

[mise](https://mise.jdx.dev) manages the toolchain, the environment and the
local services. It covers Rust, Tracey and Diesel's CLI (which bundles libpq,
so no system Postgres client is needed).

```sh
mise trust && mise install
mise run db:up      # Postgres 18 in Docker on localhost:55432, waits until healthy
```

mise sets `DATABASE_URL` for the local database. Other database tasks:

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
