# konklav-relying-client

Native Rust host binding for the relying core, on tokio and reqwest.

## Responsibilities

- Logging in as a service principal with a secret key and renewing the token.
- Following `/v1/events` (SSE), resuming with `Last-Event-ID`, and reporting heartbeats, events and disconnects to the core.
- Running the core's background work: JWKS and entitlement refreshes.
- `decide`:
  1. Asks the core.
  2. Fetches whatever it needs and asks again.
  3. Asks `/v1/check` when the core says the caches can't be trusted.

  Errors mean deny. `decide_request` takes a `Presented` (the request's raw `Authorization` and `DPoP` headers and the public URL it addressed) so sender-constrained tokens work too; `decide` takes a bearer token.
- `accept_request`, `decide_accepted` and `verify_request`, for hosts that need a request's verified claims before they can state its requirements (`relying.verify.accepted-presentation`): `accept_request` verifies the token, its session and its DPoP proof once and returns the claims with a handle; `decide_accepted` decides once for the handle without checking the proof again; `verify_request` verifies without deciding. Each falls back to `/v1/check` like `decide`, and returns `Verified::{Valid, Invalid, InvalidProof}`.
- `await_cursor` for read-your-writes after a Konklav write.
- Erasure, for relying systems that keep data about subjects ([erasure](../../docs/architecture/erasure.md#through-the-relying-sdk)):
  - `erasures()` returns a channel of `ErasureNotice`: `Erased` for each subject Konklav erases, and `Missed` when some may have been missed, which includes every start. Ask for it before `start()`.
  - `erased_subjects(since)` reads every subject erased at or after a time from `/v1/erased-subjects`, for catching up.

  ```rust
  let mut erasures = client.erasures();
  let _tasks = client.start();
  while let Some(notice) = erasures.recv().await {
      match notice {
          ErasureNotice::Erased(erased) => delete_everything_about(erased.subject).await,
          ErasureNotice::Missed { .. } => {
              for erased in client.erased_subjects(stored_watermark().await).await? {
                  delete_everything_about(erased.subject).await;
              }
          }
      }
  }
  ```
- `pacing` and `fake_ids`, so a relying system's own endpoints don't show, through their timing or their ids, whether a record exists:
  - `paced(Pacing::new(floor, jitter), work)` runs the work and a wait drawn from `floor ± jitter` together, and returns once both are done, an `Err` included. Dropping it drops the wait; a panic isn't paced. Tests use `Pacing::NONE`.
  - `fake_uuid7()` makes a UUIDv7 claiming now, for something the request would have just created; `fake_uuid7_within(window)` claims a millisecond from a past window, for something that would already exist. `claimed_ms` reads back the time a UUIDv7 claims.
- `rate_limit::RateLimit`: `add(key)` counts an event or returns `RateLimited`. With the `redis` feature, `RateLimit::with_redis` shares the limit through Valkey or Redis (a `ConnectionManager` the application owns, and a secret every process shares), giving up on the store after a timeout (100 ms by default) and answering from memory while it fails.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-relying` | All decision and cache rules |
| `konklav-server` | The relying and subject-facing surfaces it talks to |
| `konklav-axum` | Builds route policies for axum on it |

## Running

This is a library; construct a `RelyingClient` and call `start()`.

## Testing

```sh
mise run db:up
cargo test -p konklav-relying-client
cargo test -p konklav-relying-client --features redis
```

- Direct coverage: end to end against a real server on ephemeral ports:
  - check-API fallback before the feed connects, then local decisions
  - revocation through the feed
  - erasure: the notice at start, the live notice, and reading the list
  - read-your-writes after removing an assignment
  - accepting a request once and deciding for it once
- Rate limits against the development Valkey (`REDIS_URL`): one limit shared by two clients, refusals that don't count, hashed and expiring keys, and falling back to memory and recovering when a proxy cuts the connection.
- Pacing and fake ids (`tests/pacing.rs` and the modules' own tests): the work and the wait together, errors waiting and cancellation and panics not, the delay's range, and the layout and claimed time of fake ids.

## Traceability and related docs

- [Native relying host spec](../../docs/spec/software-items/relying-client.md) (`item.relying-client.*`)
- [Relying systems spec](../../docs/spec/relying-systems.md)
- [Relying SDK](../../docs/architecture/relying-sdk.md)
