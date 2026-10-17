# conclave-store

Library crate that owns Conclave's Postgres database: schema, forward-only migrations, connection pool and, from M2, repositories.

## Responsibilities

- Building the async connection pool (`connect`) and checking the database is reachable (`ping`).
- Embedding the migrations from `migrations/`, listing the pending ones (`pending_migrations`) and applying them (`run_pending_migrations`).
- The Diesel schema in `src/schema.rs`. It is generated, so don't edit it by hand: run `mise run db:schema`.
- The `event` outbox table that the change feed is built on.

## Public interface

- `connect`, `ping`, `ConnectOptions`, `Pool`
- `pending_migrations`, `run_pending_migrations`
- `schema`

The migration functions use Diesel's blocking harness, so they must run on a multi-threaded tokio runtime.

## Relationships

| Software item | Relationship |
|---|---|
| `conclave-core` | Shared identifier types |
| `conclave-server` | Runs migrations (`migrate`) and checks them for readiness |
| `conclave-test-support` | Creates isolated, migrated databases for tests |
| PostgreSQL | Conclave's exclusive, authoritative store |

## Usage

New migration:

```sh
cd items/store && diesel migration generate --no-down <name>
```

Write `up.sql`, then run `mise run db:schema` to apply it locally and regenerate `schema.rs`. Migrations are forward-only, so there is no `down.sql`.

## Running

This is a library and can't run on its own. Apply migrations to the local database with `mise run migrate`.

## Testing

```sh
mise run db:up
cargo test -p conclave-store
```

- Direct coverage: migration discovery, idempotent application and pending detection, each in its own database.
- Indirect coverage: the server readiness tests.

## Traceability and related docs

- [Platform spec: storage](../../docs/spec/platform.md)
- [Storage architecture](../../docs/architecture/storage.md)
- [Traceability guidance](../../docs/traceability-guidance.md)
- [Nomenclature](../../docs/nomenclature.md)
