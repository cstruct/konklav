# Change Feed

Events, cursors and transport.

## Events

r[feed.outbox]
Events MUST be appended to an ordered outbox in the same transaction as the
change they describe. Every event MUST have a strictly increasing cursor.

r[feed.kinds]
The change feed MUST include at least these event kinds:
- `session.changed`
- `entitlements.changed`
- `tenant.changed`
- `share.changed`
- `scope.changed`
- `signing_keys.changed`
- `delivery.requested`

r[feed.self-contained-session]
`session.changed` events MUST carry enough state (session id, version,
revoked flag) for consumers to apply them without calling back.

r[feed.retention]
Events MUST be retained for at least a configured period. A consumer whose
cursor is older than retention MUST be told so explicitly.

r[feed.authorization]
Consumers MUST authenticate as service principals and MUST be authorized
per event kind.

## Transport

r[feed.sse]
The change feed MUST be served as Server-Sent Events. Each event's SSE `id`
MUST be its cursor, and consumers MUST be able to resume with
`Last-Event-ID`.

r[feed.sse.kinds-filter]
Consumers MUST be able to subscribe to a subset of event kinds.

r[feed.sse.heartbeat]
The server MUST send a heartbeat at a fixed interval (10 seconds by default)
while a stream is idle.

r[feed.reset]
When a consumer resumes from a cursor that is older than retention, or that
cannot be resumed for any other reason, the server MUST send a `reset` event
before continuing. Consumers MUST treat a reset as "every cached state may be
stale".

r[feed.batch]
Konklav MUST also serve the feed as paged JSON (`after` a cursor, limited
page size) for consumers that cannot hold a stream open.

r[feed.at-least-once]
Delivery MUST be at-least-once. Consumers own their cursors, and handlers
MUST tolerate repeated events.

r[feed.notify-hint-only]
In-process wake-ups (for example Postgres `NOTIFY`) MAY be used to push new
events to open streams sooner, but correctness MUST NOT depend on them.
