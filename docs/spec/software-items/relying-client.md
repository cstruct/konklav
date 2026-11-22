# Native Relying Host Software Item

Stable implementation contracts owned by `konklav-relying-client`, the
native Rust host binding for the relying core. Its decisions follow the
relying-system rules (`relying.*`) and the core's (`item.relying.*`); this
file holds what the binding adds on its own.

## HTTP

r[item.relying-client.http]
`RelyingClient` MUST give up connecting to Konklav, and on any request but
the change feed's, after 10 seconds, and on the change feed's stream once
nothing arrived for as long as the core takes to stop trusting it
(`relying.fallback.lag`). It MUST NOT follow redirects, which would send
the secret key or a token wherever a redirect points. `ClientConfig`'s
`Debug` output MUST NOT show the secret.

r[item.relying-client.path-segments]
`RelyingClient` MUST ask Konklav for a registered scope with its kind and
id as one percent-encoded path segment each, and MUST NOT ask at all for a
kind or id that is empty, `.` or `..`: a URL takes those for dot segments
however they are encoded, so the request would go to another path. It MUST
instead tell the core that Konklav doesn't know the scope
(`relying.cache.registered-unknown`).

r[item.relying-client.fetch-reported]
`RelyingClient` MUST report to the core every fetch the core asked for:
its result, or its failure (`on_fetch_failed`), also for a fetch given up
because the request that needed it was dropped. The core takes a fetch to
be in flight until then, and asks for no other JWKS meanwhile
(`relying.fallback.signing-keys`).

## Pacing and fake ids

The binding offers pacing (see the nomenclature) and fake ids for a relying
system's own endpoints, as the Python binding does (`item.py.pacing.*`,
`item.py.fake-id.*`). Both are host-level timing and id generation, not
decision logic, so they live in the host binding rather than in the
relying core (`item.relying.sans-io`).

r[item.relying-client.pacing.delay]
`Pacing { floor, jitter }` MUST draw each wait uniformly from
`floor ± jitter`, with microsecond resolution, from the operating system's
randomness, and MUST clamp it at zero, as the server's pacing does
(`authn.pacing`). `Pacing::NONE` MUST wait not at all, so tests need no
other way to turn pacing off.

r[item.relying-client.pacing.concurrent]
`paced(pacing, work)` MUST draw the wait when it starts the work, and
finish when both the work and the wait are done, so the floor adds no
latency when the work takes longer. It MUST return the work's output.

r[item.relying-client.pacing.errors]
`paced` MUST wait whatever the work returns, an `Err` included, since a
failure that answers early is the timing difference pacing hides.

r[item.relying-client.pacing.cancellation]
Dropping the future `paced` returns MUST drop the wait with it, and a panic
in the work MUST propagate without waiting. Whoever cancelled isn't waiting
for an answer, so there is no timing to hide, and waiting would hold up
timeouts and shutdown.

r[item.relying-client.fake-id.layout]
`fake_uuid7` and `fake_uuid7_within` MUST return a UUID of version 7 and
the RFC 9562 variant, with a 48-bit Unix timestamp in milliseconds, and its
74 other bits drawn from the operating system's randomness.

r[item.relying-client.fake-id.time]
The caller MUST choose the time a fake id claims: the current millisecond
(`fake_uuid7`), to stand in for something just created, or, with a past
window (`fake_uuid7_within`), a millisecond drawn uniformly from that window
up to now, to stand in for something created some time ago. A window MUST
be positive.
