# Change Feed

Events, cursors and transport.

## Events

r[feed.outbox]
Events MUST be appended to an ordered outbox in the same transaction as the
change they describe. Every event MUST have a strictly increasing cursor.

r[feed.commit-order]
Cursors MUST become visible in increasing order: once an event can be read,
every event with a lower cursor that will ever commit already has, so a
reader that resumes after the last cursor it read misses nothing, however
transactions interleave.

r[feed.kinds]
The change feed MUST include at least these event kinds:
- `session.changed`
- `entitlements.changed`
- `tenant.changed`
- `share.changed`
- `scope.changed`
- `signing_keys.changed`
- `delivery.requested`
- `subject.erased`

r[feed.self-contained-session]
`session.changed` events MUST carry enough state (session id, version,
revoked flag) for consumers to apply them without calling back.

r[feed.subject-erased]
A `subject.erased` event MUST carry the subject's id and the time of
erasure, and nothing that identifies the person. It MUST be readable by
every consumer of the feed, like the other events that name subjects.

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

r[feed.sse.position]
Every stream MUST begin with an event that carries the cursor it starts
after, whatever kinds the consumer subscribed to: a `reset` when
`feed.reset` applies, and a `position` event otherwise. A consumer that
connects without a cursor thereby learns where it stands before any later
event arrives, and by `feed.commit-order` every event at or below that
cursor has already committed.

r[feed.batch]
Konklav MUST also serve the feed as paged JSON (`after` a cursor, limited
page size) for consumers that cannot hold a stream open.

r[feed.at-least-once]
Delivery MUST be at-least-once. Consumers own their cursors, and handlers
MUST tolerate repeated events.

r[feed.notify-hint-only]
In-process wake-ups (for example Postgres `NOTIFY`) MAY be used to push new
events to open streams sooner, but correctness MUST NOT depend on them.
