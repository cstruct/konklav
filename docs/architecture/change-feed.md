# Change feed

## Endpoints

- `GET /v1/events?kinds=a,b` (SSE). The SSE `id` of each event is its
  cursor, and clients resume with `Last-Event-ID`. A comment line is sent
  every 10 s as a heartbeat.
- `GET /v1/events/batch?after=<cursor>&kinds=…&limit=…` returns
  `{ events, next }` as JSON.

## Server side

Every open stream:

1. Replays events after the client's cursor from the outbox.
2. Waits on an in-process broadcast that the `LISTEN` connection fires, or
   on a poll interval as fallback.
3. Reads forward from its last cursor.

Because streams always read the outbox, a missed wake-up only adds latency.

Cursor gaps from rolled-back identity values are harmless, so pruning can't
be detected from gaps. Retention instead records the highest pruned cursor
in `feed_watermark`. A consumer resuming below the watermark, or from a
cursor ahead of the outbox, gets a `reset` event (whose `id` is the
watermark) and continues from there. Without a cursor, a stream starts at
the head: new consumers don't replay history.

Other relying endpoints:

- `GET /v1/session-states/{id}` returns a session in the `session.changed`
  shape, for caches that haven't seen it yet.
- `GET /v1/entitlements/{subject}[/{tenant}]` returns an entitlement set.

## Event payloads

| Kind | Payload |
|---|---|
| `session.changed` | `{ session, subject, version, revoked, expires_at }` |
| `entitlements.changed` | `{ subjects: [..] }` or `{ all: true }`, plus an optional `tenant` |
| `tenant.changed` | `{ tenant, parent, state, created }` |
| `signing_keys.changed` | `{ kids: [..] }` |
| `delivery.requested` | `{ channel, recipient, purpose, subject?, material, expires_at, locale_hint? }` |

Every event also carries `cursor`, `kind` and `created_at`.

## Delivery requests

Konklav mints challenges and emits a `delivery.requested` event for each.
The relying system's delivery worker:

- reads the batch endpoint with its own cursor
- renders the message with its own templates
- sends it through its own providers
- stores its cursor only after handing the message to its provider

Delivery is at-least-once, so recipients may occasionally get a duplicate.
The challenge stays single-use either way.

Only service principals with the delivery capability can read
`delivery.requested`. Its material expires with the challenge
(`r[challenge.delivery.no-replay]`).

## Why SSE

SSE is plain HTTP, resumes natively, works through most proxies, and is easy
to consume from Python, Rust and browsers. Long-poll was the alternative,
but it needs more client logic for the same outcome. A message bus would
couple Konklav to one relying system's infrastructure. A relying system can
always bridge the feed into its own bus.
