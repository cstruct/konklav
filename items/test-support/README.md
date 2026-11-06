# konklav-test-support

Library crate with test helpers shared by Konklav's software items. It is only used as a dev-dependency.

## Responsibilities

- `TestDatabase`:
  - creates a uniquely named database on the development Postgres server and applies every migration to it
  - drops the database (`with (force)`) when the value is dropped
- `DpopKey`: a P-256 key standing in for a client's WebCrypto key, signing DPoP proofs with fresh `jti`s, or at a given time for tests with their own clock

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-store` | Provides the pool and migrations |
| `konklav-store`, `konklav-server` tests | Use it for isolated databases |
| `konklav-relying`, `konklav-server` tests, `konklav-examples` | Use `DpopKey` for DPoP proofs |
| `konklav-token` | Key thumbprints and access-token hashes for `DpopKey` |
| PostgreSQL | The server from `KONKLAV_TEST_DATABASE_URL`, falling back to `DATABASE_URL` (which mise sets) |

## Usage

```rust
#[tokio::test(flavor = "multi_thread")]
async fn stores_things() {
    let db = konklav_test_support::TestDatabase::new().await;
    let pool = db.pool();
    // ...
}
```

Database tests must use the multi-threaded runtime, because applying migrations blocks a thread.

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p konklav-test-support
```

- Direct coverage: database URL rewriting.
- Indirect coverage: every database test in the workspace.

## Traceability and related docs

- [Storage architecture](../../docs/architecture/storage.md)
- [Nomenclature](../../docs/nomenclature.md)
