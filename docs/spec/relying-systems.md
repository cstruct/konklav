# Relying Systems

Obligations on the relying core and its host bindings, which together make
up the relying SDK.

## Verification

r[relying.verify.offline]
The relying SDK MUST verify access tokens offline against cached JWKS:
signature, `iss`, `aud`, `exp`, token kind.

r[relying.verify.audiences]
A relying system MAY accept access tokens for several audiences, such as
Konklav's own and those of the OIDC clients that sign people in to it. The
relying SDK MUST then accept a token whose `aud` is any one of them, and no
other, both when it verifies offline and when it decides through the check
API, and MUST return the token's `aud` with its verified claims so the
relying system can tell which audience it carried.

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

r[relying.verify.dpop]
The relying SDK MUST verify sender-constrained access tokens from the
request's `Authorization` and `DPoP` headers and a request descriptor (the
method and the URL the client addressed). Without a request descriptor, it
MUST refuse an access token carrying `cnf`.

r[relying.verify.dpop-before-check]
The relying SDK MUST verify the DPoP proof itself before it decides through
the check API. The check API MUST NOT require a DPoP proof, since the
relying system that calls it has already checked the proof.

r[relying.verify.dpop-replay]
One relying core MUST remember the `jti`s of the DPoP proofs it accepted
for as long as they could pass the freshness check, so it can refuse a
replay (`r[token.dpop.replay]`). It need not detect replays across separate
relying cores.

r[relying.verify.dpop-challenge]
When the relying SDK refuses an access token for its DPoP proof or scheme,
it MUST report that reason, so the relying system can answer with a
`WWW-Authenticate: DPoP` challenge.

r[relying.verify.accepted-presentation]
A relying system that needs a request's verified claims before it can state
the requirements, such as to find a scope from the token's tenant, gets
them without spending the request's one DPoP proof twice. The relying SDK
MUST be able to accept a request's presentation: verify the token, its
session and any DPoP proof, remember the proof as `relying.verify.dpop-replay`
requires, and return the claims with a handle for the accepted
presentation. Deciding with that handle MUST NOT check the proof again. It
MUST check the token and its session as any decision does, so a session
that ended in between is denied. A handle:

- is kept only in the memory of the relying core that issued it, and no
  other relying core knows it;
- answers at most one decision, as a proof does;
- expires once its proof could no longer pass the freshness check, or for
  a bearer token, after the same time.

A decision with a handle that is unknown, already answered or expired MUST
deny with `invalid_token`.

## Decisions

r[relying.decision.local]
With a trusted cache, the relying SDK MUST decide locally, without calling
Konklav, by evaluating the operation's requirements against the cached
entitlement set, session flags and step-up state.

r[relying.decision.requirements]
An operation's requirements MUST be expressible as: required actions at the
global, tenant and scope levels; allowed token kinds; admitted restrictive
flags; required assertive flags; step-up requirements (a minimum number of
`amr` methods, an allowed `amr` set, a maximum `auth_time` age); and
required tenant facts (`authz.decision.tenant-facts`).

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

r[relying.erasure.notify]
The relying SDK MUST hand each `subject.erased` event to the host, so the
relying system can remove its own data about the subject. It MUST drop
every cached session and entitlement set of that subject first. The host
MAY be handed the same erasure more than once.

r[relying.erasure.reset]
On a `reset` event, the relying SDK MUST tell the host that erasures may
have been missed, with the time of the last event it had applied, so the
relying system can read the erased subjects since then
(`subject.erasure.list`).

r[relying.fallback.lag]
If the feed connection is lost, or no event or heartbeat arrives for three
heartbeat intervals, the relying SDK MUST treat its cache as untrusted and
decide through the check API until it has reconnected and caught up.

r[relying.fallback.equivalence]
The relying SDK MUST report decisions made through the check API in the
same form as local decisions.

## Rate limits

r[relying.rate-limit.windows]
A rate limit MUST have a name and one or more windows, each a number of
events and a period. Each window MUST admit its number of events at once,
and after that one more each time the period divided by that number has
passed. An event MUST be admitted only when every window of its limit
admits it for its key, and a refused event MUST NOT count toward any
window.

r[relying.rate-limit.retry-after]
A refused event MUST report how long until its key would be admitted by
every window.

r[relying.rate-limit.shared]
When a rate-limit store is configured, the relying SDK MUST check and
update all of a key's windows there in one atomic step, using the store's
clock, so every process sharing the store enforces one limit together.
Limits with the same name and windows MUST share their state in the store.

r[relying.rate-limit.local]
Every process MUST also apply each event to in-memory state of its own,
whether or not a store is configured or answers, and MUST keep that state
for a bounded number of keys, the least recently used going first.

r[relying.rate-limit.fallback]
When the store fails, or doesn't answer within the limit's timeout, the
relying SDK MUST answer from its local state, and MUST NOT ask the store
again until a backoff has passed: 1 second after the first failure,
doubling with each further failure to at most 30 seconds, and reset by the
store's first answer.

r[relying.rate-limit.local-divisor]
A rate limit MUST accept an optional local divisor, 1 by default, that
divides each window's number of events in local state (rounded down, at
least 1), so that several processes answering from local state together
admit about the limit. It MUST apply to limits without a store too.

r[relying.rate-limit.key-privacy]
The relying SDK MUST NOT write rate-limit keys to the store in the clear,
only a keyed hash of each under a secret the relying system configures. A
store MUST be refused without a secret of at least 32 bytes.

r[relying.rate-limit.expiry]
A key's state MUST be dropped, in the store and in memory, once every
window would admit its full number of events again.
