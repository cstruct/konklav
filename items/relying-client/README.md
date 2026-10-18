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

  Errors mean deny.
- `await_cursor` for read-your-writes after a Conclave write.

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
```

- Direct coverage: end to end against a real server on ephemeral ports:
  - check-API fallback before the feed connects, then local decisions
  - revocation through the feed
  - read-your-writes after removing an assignment

## Traceability and related docs

- [Relying systems spec](../../docs/spec/relying-systems.md)
- [Relying SDK](../../docs/architecture/relying-sdk.md)
