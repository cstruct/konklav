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
- Rate limits (`rate_limit`): named limits of several windows per key, enforced with the generic cell rate algorithm (GCRA):
  - local state for a bounded number of keys (100 000 by default, least recently used first), dropped once drained, with an optional local divisor
  - for a rate-limit store (Redis), the script to run with its keys and arguments, keys hashed under a configured secret (HMAC-SHA-256)
  - the store's backoff while it fails (1 s, doubling to 30 s), so the host answers from local state
- Read-your-writes: `await_cursor` is ready once the feed has passed the cursor and every entry it invalidated has been refreshed.
- Sender-constrained (DPoP) tokens: from a request's raw `Authorization` and `DPoP` headers and its request descriptor (the method and the public URL the client addressed):
  - a token with `cnf` needs the `DPoP` scheme and a valid proof; under `Bearer`, or without a request descriptor, it is denied with `invalid_dpop_proof`
  - the proof is checked before anything else, including before a hand-off to the check API, which never sees it
  - accepted proofs are remembered for the freshness window (60 s), bounded (100 000 by default; when full of fresh proofs, new ones are refused), and only once the core has answered, so a host's fetch-and-retry isn't a replay

The core never makes network calls, reads clocks, spawns tasks or sleeps. Hosts pass the time (Unix ms) and the data in, and ask `decide` and `poll_work`.

## Public interface

- `Relying::decide` returns `Outcome::Decided` or `Outcome::Need { needs }`. `decide_presented` and `verify_presented` take a `Presented` (raw headers and a `RequestDescriptor`) for DPoP; `decide` and `verify` take a bearer token. `accept_presented` verifies a `Presented` once and holds it under a `PresentationId` for one `decide_accepted`, which doesn't check the proof again.
- `Verification::InvalidProof` and `DenyReason::InvalidDpopProof` mean the relying system should answer with a `WWW-Authenticate: DPoP` challenge.
- `Relying::poll_work` returns the fetches due and when to poll next.
- `on_jwks`, `on_session`, `on_session_unknown`, `on_entitlements`, `on_registered_scope`, `on_registered_scope_unknown`, `on_fetch_failed`, `on_feed_connected`, `on_feed_activity`, `on_feed_lost`, `on_feed_event`, `await_cursor`.
- `Config` holds the issuer, audience and tuning.
- `rate_limit::RateLimiter`: `begin` counts an event locally and returns `Attempt::Decided` or `Attempt::Store { call, local }`; `on_store_answer` and `on_store_failed` take the store's answer or failure. `STORE_SCRIPT` is the script both hosts run.

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
  - DPoP: schemes, proofs checked before the check API, replays, the bounded replay set
  - rate limits: bursts and intervals, several windows, refusals that don't count, the local divisor, the key bound and expiry, store calls and backoff
- Indirect coverage: the native client's end-to-end tests against a real server, the Python tests, and both hosts' rate-limit tests against a real Redis, which run `STORE_SCRIPT`.

## Traceability and related docs

- [Relying systems spec](../../docs/spec/relying-systems.md) and [item spec](../../docs/spec/software-items/relying.md)
- [Relying SDK](../../docs/architecture/relying-sdk.md)
- [Nomenclature](../../docs/nomenclature.md)
