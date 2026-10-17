# conclave-test-support

Library crate with test helpers shared by Conclave's software items. It is only used as a dev-dependency.

## Responsibilities

- `TestDatabase`:
  - creates a uniquely named database on the development Postgres server and applies every migration to it
  - drops the database (`with (force)`) when the value is dropped

## Relationships

| Software item | Relationship |
|---|---|
| `conclave-store` | Provides the pool and migrations |
| `conclave-store`, `conclave-server` tests | Use it for isolated databases |
| PostgreSQL | The server from `CONCLAVE_TEST_DATABASE_URL`, falling back to `DATABASE_URL` (which mise sets) |

## Usage

```rust
#[tokio::test(flavor = "multi_thread")]
async fn stores_things() {
    let db = conclave_test_support::TestDatabase::new().await;
    let pool = db.pool();
    // ...
}
```

Database tests must use the multi-threaded runtime, because applying migrations blocks a thread.

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p conclave-test-support
```

- Direct coverage: database URL rewriting.
- Indirect coverage: every database test in the workspace.

## Traceability and related docs

- [Storage architecture](../../docs/architecture/storage.md)
- [Nomenclature](../../docs/nomenclature.md)
