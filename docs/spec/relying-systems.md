# Relying Systems

Obligations on the relying core and its host bindings, which together make
up the relying SDK.

## Verification

r[relying.verify.offline]
The relying SDK MUST verify access tokens offline against cached JWKS:
signature, `iss`, `aud`, `exp`, token kind.

r[relying.verify.foreign-keys]
The relying SDK MUST accept a JWKS that also holds keys it doesn't verify
access tokens with, such as ID-token keys of other types, and MUST ignore
them.

r[relying.verify.jwks-refresh]
The relying SDK MUST refresh JWKS on `signing_keys.changed` events and on an
unknown `kid`. Refreshes caused by unknown `kid`s MUST be rate-limited.

r[relying.verify.session]
The relying SDK MUST reject tokens whose session is known to be revoked or
whose `sv` is below the session's latest known version.

## Decisions

r[relying.decision.local]
With a trusted cache, the relying SDK MUST decide locally, without calling
Konklav, by evaluating the operation's requirements against the cached
entitlement set, session flags and step-up state.

r[relying.decision.requirements]
An operation's requirements MUST be expressible as: required actions at the
global, tenant and scope levels; allowed token kinds; admitted restrictive
flags; required assertive flags; and step-up requirements (a minimum number
of `amr` methods, an allowed `amr` set, a maximum `auth_time` age).

r[relying.decision.fail-closed]
If the relying SDK can neither decide locally nor reach the check API, it
MUST deny.

## Entitlement cache

r[relying.cache.ttl]
Cached entitlement sets MUST expire after a configured TTL (15 minutes by
default).

r[relying.cache.background-refresh]
The relying SDK MUST refresh entries that are invalidated or close to
expiry in the background, debounced and coalesced per (subject, tenant), so
that frequently used entries do not expire on the request path.

r[relying.cache.debounce-bound]
After an `entitlements.changed` event, an affected entry MAY be used for at
most the debounce window (500 ms by default). After that, decisions for it
MUST wait for the refreshed entitlement set.

r[relying.cache.wildcard-sweep]
An all-subjects invalidation MUST mark every entry stale and refresh them in
a rate-limited sweep, still subject to the debounce bound.

r[relying.cache.session-immediate]
`session.changed` events MUST take effect immediately, without debounce.

r[relying.cache.await-cursor]
The relying SDK MUST let callers wait until it has applied all events up to
a given cursor, so that a relying system can read its own writes.

r[relying.cache.registered]
The relying SDK MUST fetch a registered scope's record the first time a
decision needs it, and keep it in a bounded cache with the same TTL as
entitlement sets. It MUST NOT need every registered scope in advance.

r[relying.cache.registered-unknown]
The relying SDK MUST cache that a registered scope is unknown for a
configured period (5 seconds by default), and drop that entry when a
`scope.changed` event names the scope.

r[relying.cache.registered-debounce]
After a `scope.changed` event names a cached registered scope, its record
MAY be used for at most the debounce window. After that, decisions for it
MUST wait for the refreshed record.

## Feed and fallback

r[relying.feed.consume]
The relying SDK MUST consume the change feed for the event kinds it caches,
keeping its cursor.

r[relying.feed.position]
The relying SDK MUST take a stream's `position` event as its cursor, so that
waiting for a cursor at or below it succeeds without a later event.

r[relying.feed.reset]
On a `reset` event, the relying SDK MUST treat every cached session,
entitlement set and registered scope as stale.

r[relying.fallback.lag]
If the feed connection is lost, or no event or heartbeat arrives for three
heartbeat intervals, the relying SDK MUST treat its cache as untrusted and
decide through the check API until it has reconnected and caught up.

r[relying.fallback.equivalence]
The relying SDK MUST report decisions made through the check API in the
same form as local decisions.
