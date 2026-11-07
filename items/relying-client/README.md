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
- `await_cursor` for read-your-writes after a Konklav write.
- `rate_limit::RateLimit`: `add(key)` counts an event or returns `RateLimited`. With the `redis` feature, `RateLimit::with_redis` shares the limit through Valkey or Redis (a `ConnectionManager` the application owns, and a secret every process shares), giving up on the store after a timeout (100 ms by default) and answering from memory while it fails.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-relying` | All decision and cache rules |
| `konklav-server` | The relying and subject-facing surfaces it talks to |

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
  - read-your-writes after removing an assignment
- Rate limits against the development Valkey (`REDIS_URL`): one limit shared by two clients, refusals that don't count, hashed and expiring keys, and falling back to memory and recovering when a proxy cuts the connection.

## Traceability and related docs

- [Relying systems spec](../../docs/spec/relying-systems.md)
- [Relying SDK](../../docs/architecture/relying-sdk.md)
