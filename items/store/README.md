# konklav-store

Library crate that owns Konklav's Postgres database: schema, forward-only migrations, connection pool and, from M2, repositories.

## Responsibilities

- Building the async connection pool (`connect`) and checking the database is reachable (`ping`).
- Embedding the migrations from `migrations/`, listing the pending ones (`pending_migrations`) and applying them (`run_pending_migrations`).
- The Diesel schema in `src/schema.rs`. It is generated, so don't edit it by hand: run `mise run db:schema`.
- The `event` outbox table that the change feed is built on.
- Repositories:
  - `subjects`
  - `credentials`: one table for every kind; kind-specific `data` is `jsonb` that the database checks against a JSON Schema per kind with pg_jsonschema
  - `sessions`: refresh rotation with reuse detection, revocation by filter, and a `session.changed` event for every change in the same transaction
  - `signing_keys`: published public keys and their rotation state
  - `login_attempts`: rate limiting
  - `events`, including `last_in_transaction` for write cursors
  - `tenants` (the root is the nil UUID) and `memberships`
  - `catalog`: one document of actions, groups, scope kinds, facts and session flags
  - `templates`, `roles`, and role assignments (membership or global)
  - `compile_input`: everything the compiler needs for one subject and tenant, read in one repeatable-read snapshot (`load`), or inside a caller's transaction (`read`)
  - `history`: enabling and disabling history, how far back it reaches, and `shadow`, which makes the rest of a transaction read tracked tables as of a past time
- Triggers append `entitlements.changed` and `tenant.changed` for every write to memberships, assignments, subject state, the catalog, templates, roles and tenants.
- While history is enabled, triggers record a row version for every write to those tables and to shares (`row_version`).

## Public interface

- `connect`, `ping`, `ConnectOptions`, `Pool`
- `pending_migrations`, `run_pending_migrations`
- `schema`

The migration functions use Diesel's blocking harness, so they must run on a multi-threaded tokio runtime.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-core` | Shared identifier types |
| `konklav-server` | Runs migrations (`migrate`) and checks them for readiness |
| `konklav-test-support` | Creates isolated, migrated databases for tests |
| PostgreSQL | Konklav's exclusive, authoritative store. It needs the [pg_jsonschema](https://github.com/supabase/pg_jsonschema) extension; the dev image in `dev/postgres` includes it |

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
cargo test -p konklav-store
```

- Direct coverage:
  - migrations
  - JSON Schema rejection of invalid credential data
  - identifier uniqueness and credential history
  - refresh rotation and reuse detection
  - revocation filters and their events
  - signing-key rotation and revocation
- Indirect coverage: the server readiness tests.

## Traceability and related docs

- [Platform spec: storage](../../docs/spec/platform.md) and [item spec](../../docs/spec/software-items/store.md)
- [Storage architecture](../../docs/architecture/storage.md)
- [Traceability guidance](../../docs/traceability-guidance.md)
- [Nomenclature](../../docs/nomenclature.md)
