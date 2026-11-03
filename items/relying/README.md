# konklav-relying

The relying core: a sans-I/O library with everything a relying system needs to decide locally. It is shared by every host binding.

## Responsibilities

- Verifying access tokens offline against cached JWKS. Unknown key ids trigger a JWKS refresh, rate-limited.
- Tracking session states from `session.changed` events, which apply immediately, and rejecting revoked or superseded sessions.
- Caching entitlement sets:
  - with a TTL (15 min)
  - honouring a removed grant for at most the debounce window (500 ms)
  - refreshing busy entries in the background
  - sweeping wildcard invalidations in batches
- Caching registered scopes' records, fetched the first time a decision needs one (`Need::RegisteredScope`):
  - bounded, least recently used first (100 000 by default), with the entitlement TTL
  - scopes Konklav doesn't know are remembered for 5 s, and forgotten as soon as `scope.changed` names them
  - `scope.changed` marks a record stale with the same debounce bound as entitlement sets
- Following the change feed's state: cursor, heartbeats, `position`, `reset`. When it lags (three missed heartbeats), the core answers `Need::Check`, so hosts ask `/v1/check`.
- Read-your-writes: `await_cursor` is ready once the feed has passed the cursor and every entry it invalidated has been refreshed.

The core never makes network calls, reads clocks, spawns tasks or sleeps. Hosts pass the time (Unix ms) and the data in, and ask `decide` and `poll_work`.

## Public interface

- `Relying::decide` returns `Outcome::Decided` or `Outcome::Need { needs }`.
- `Relying::poll_work` returns the fetches due and when to poll next.
- `on_jwks`, `on_session`, `on_session_unknown`, `on_entitlements`, `on_registered_scope`, `on_registered_scope_unknown`, `on_fetch_failed`, `on_feed_connected`, `on_feed_activity`, `on_feed_lost`, `on_feed_event`, `await_cursor`.
- `Config` holds the issuer, audience and tuning.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-token` | Token verification and JWKS |
| `konklav-authz` | `evaluate`, `Requirements`, `EntitlementSet` |
| `konklav-core` | Ids, cursors, feed wire types (without id generation, so it builds for wasm) |
| `konklav-relying-client` | Native Rust host |
| `konklav-py` | Python host |

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p konklav-relying
cargo build -p konklav-relying --target wasm32-unknown-unknown
```

- Direct coverage: deterministic tests with injected time, covering:
  - warm and cold decisions, fallback when lagging
  - session revocation, the debounce bound, TTL, reset
  - JWKS refresh limits, await-cursor, sweeps, tenant-scoped invalidation
  - registered scopes: lazy fetches, unknown scopes, moves within the debounce window, the size bound
- Indirect coverage: the native client's end-to-end tests against a real server, and the Python tests.

## Traceability and related docs

- [Relying systems spec](../../docs/spec/relying-systems.md) and [item spec](../../docs/spec/software-items/relying.md)
- [Relying SDK](../../docs/architecture/relying-sdk.md)
- [Nomenclature](../../docs/nomenclature.md)
