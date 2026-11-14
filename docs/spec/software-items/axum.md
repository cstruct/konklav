# axum Integration Software Item

Stable implementation contracts owned by `konklav-axum`, the axum
integration of the native Rust host binding: route policies on axum routes,
evaluated by the relying core through `konklav-relying-client`. It is the
Rust counterpart of `konklav-fastapi` (`item.py-fastapi.*`) and answers
alike.

It builds on `konklav_relying::policy::Policy` (`item.relying.policy.*`)
and only translates between it, the relying client and axum: every
decision is the relying core's.

## Packaging

r[item.axum.published]
The crate MUST be published to crates.io with the other published crates,
at the version of the Konklav release it was built with, and MUST require
`konklav-relying` and `konklav-relying-client` at exactly that version.

r[item.axum.relying-host]
The crate MUST reach the relying SDK only through a trait for accepting a
request's presentation, deciding for an accepted presentation and verifying
a presentation without a decision, implemented for
`konklav_relying_client::RelyingClient`, so that a relying system can wrap
the client and tests can stand in for it.

r[item.axum.configuration]
`Konklav` MUST hold what evaluating route policies needs from the
application: the relying host, a scope resolver per scope kind, an optional
route-tenant resolver, hooks run on every verified token, an optional cookie
hook, the public URL behind a proxy, trusted proxies and an optional answer
for outcomes (`item.axum.respond-with`). The application MUST install it
once on its router, as a request extension. A route policy evaluated
without it MUST fail closed (`item.axum.misconfiguration`).

## Route policies

r[item.axum.route-policy]
`RoutePolicy` MUST be a tower layer that a relying system applies to a
route (its `MethodRouter`), holding the route's complete route policy:
`RouterPolicy::route(own)` MUST merge with `Policy::merge`
(`item.relying.policy.merge`) the route policies of the routers around the
route, outermost first as `RouterPolicy::nest` stacked them, then the
route's own. `RoutePolicy::new(own)` makes one with no router around it.

r[item.axum.admit-flags-operation]
Admitting a restrictive flag MUST be the operation's decision alone, as
for `item.py-fastapi.admit-flags-operation`: `RouterPolicy::route` MUST
refuse to build a `RoutePolicy` when a router's route policy sets
`admit_flags`, so only the route's own route policy admits flags.

r[item.axum.public]
A route whose merged route policy is public (`item.relying.policy.public`)
MUST be served without reading or verifying a token, and without a
decision.

## Evaluation

r[item.axum.token-extraction]
The token MUST be taken as `item.py-fastapi.token-extraction` takes it:
from the `Authorization` header (with the `DPoP` header), else from the
cookie hook if configured, else, for websocket upgrade requests only, from
the `token` query parameter. A token from the cookie hook or the query
parameter MUST be presented with the `DPoP` scheme when a `DPoP` header is
present and as a bearer token otherwise.

r[item.axum.verify-then-decide]
A route that isn't public MUST accept the request's presentation once
(`relying.verify.accepted-presentation`) with the presented `Authorization`
and `DPoP` values, the request's method (`GET` for a websocket upgrade) and
its URL as the client addressed it: the public-URL hook's, else the
request's own scheme and authority, else `http://` and its `Host` header.
Only then, in this order, MUST it run the hooks, check the route tenant,
resolve the scopes and decide, so no application code sees claims that
weren't verified.

r[item.axum.single-decision]
A route that isn't public MUST make exactly one decision per request, for
the accepted presentation and the requirements its merged route policy
(`item.relying.policy.requirements`) resolves to with the request's scopes,
marked as the request's route decision (`relying.verify.route-authority`).
A request that meets a second `RoutePolicy` after one has evaluated it MUST
fail closed (`item.axum.misconfiguration`) instead of deciding again.

r[item.axum.request-decider]
An allowed request MUST carry, for its handler, a request decider that
decides further requirements for the accepted presentation
(`relying.verify.accepted-presentation`), as the route's own decision is
made but without checking the proof again and never as the route decision,
so with the route's route authority (`relying.verify.route-authority`),
and that fails closed. Once the
handler has answered, the layer MUST release the presentation, so the
request decider decides nothing after its request.

r[item.axum.scope-resolvers]
The relying system MUST be able to configure one scope resolver per scope
kind, an async function of the request's parts and the verified token,
returning a `ResolvedScope` that names the id and optionally the scope kind
the decision uses and the scope's owner tenant, as
`item.py-fastapi.scope-resolvers` describes. A scope kind without a
resolver MUST be resolved from the path parameter of the kind's name. The
request's path parameters MUST be available to resolvers.

r[item.axum.token-tenant]
When the relying system configures a route-tenant resolver and it returns
a tenant for the request, a route that isn't public MUST deny, before
deciding, when that tenant isn't the token's `tid`, with the deny reason
`token_tenant` (`item.py.policy.token-tenant`).

r[item.axum.hooks]
The relying system MUST be able to configure hooks, async functions of the
request's parts and the verified token, which MUST run in order on every
token this crate verifies, before the route tenant, the scope resolvers and
the decision, and before any handler receives it. A hook refuses the token
by returning a response, which answers the request.

r[item.axum.outcomes]
Evaluation MUST end in an allow, after which the request proceeds, or in a
`Denied` answered with the status, JSON body and `WWW-Authenticate`
challenge `item.py-fastapi.outcomes` gives the same outcome:

- `Unauthenticated` (401) for `missing_token` (challenged `Bearer, DPoP`),
  `invalid_token` (challenged in the scheme the token was presented with)
  and `invalid_dpop_proof` (challenged `DPoP error="invalid_dpop_proof"`);
- `Forbidden` (403) for any other deny, carrying its deny reason as Konklav
  writes it, and for `token_tenant`;
- `StepUpRequired` (401) for a step-up demand, carrying its requirement,
  challenged in the token's scheme as
  `error="insufficient_user_authentication"` (RFC 9470), with `max_age`
  when the requirement has one;
- `Unavailable` (503, `konklav_unavailable`) when no decision can be
  reached (`relying.decision.fail-closed`).

r[item.axum.respond-with]
`Denied` MUST implement `IntoResponse` with the default answers above, and
the relying system MUST be able to replace the answer this crate gives for
every `Denied`, from route policies, extractors and rate limits alike.

r[item.axum.websockets]
Since a layer runs before a websocket upgrade, a websocket upgrade request
that is denied or rate limited MUST be answered with the HTTP status its
outcome has, refusing the upgrade.

## Rate limits

r[item.axum.rate-limit]
`RouteRateLimit(limit, key)` MUST add one event to the
`konklav_relying_client::rate_limit::RateLimit` `limit` for each request,
either as a tower layer of its own or attached to a `RoutePolicy` with
`RoutePolicy::rate_limit`, where it counts the requests the policy allows,
after the decision. `key` MUST be either a template or an async function of
the request's parts and the verified token, if any, returning the key.

r[item.axum.rate-limit-template]
A template MUST be parsed as `item.py-fastapi.rate-limit-template` parses
one: literal text and `{path:<name>}`, `{token:sub|sid|knd|tid}` and
`{client:address}` fields, with `{{` and `}}` for literal braces, refused
when it is created if malformed. Its token MUST be the one the route's
policy verified. Its key MUST be the parts as a compact JSON array of
strings with every character outside ASCII escaped, so that different values
can't render the same key and the same values render the same key as
`konklav-fastapi`.

r[item.axum.rate-limit-template-validation]
`RoutePolicy::rate_limit` MUST refuse a template that names a token claim
when the route policy is public, or `tid` when it admits token kinds other
than `tenant`. A template naming a path parameter the route doesn't have,
or a token claim where no route policy verified a token, MUST fail closed
when a request renders it (`item.axum.misconfiguration`).

r[item.axum.client-address]
`Konklav::client_address` MUST answer the request's peer address (axum's
`ConnectInfo<SocketAddr>`) unless the peer is one of the trusted proxies
(addresses or networks in CIDR notation, IPv4-mapped IPv6 addresses read as
IPv4). Then it MUST answer the last address in `X-Forwarded-For` that isn't
a trusted proxy, or the first when all are, or the peer without one, like
the server's `platform.server.client-address`. A request without a peer
address MUST be refused rather than given an empty key.

r[item.axum.rate-limited]
A refused event MUST be answered as `Denied::RateLimited`: 429, a JSON body
with the code `rate_limited`, and a `Retry-After` header of the
retry-after time in whole seconds, rounded up, plus random jitter of up to a
tenth of it and at least a second (`platform.error.retry-after`).
`konklav_relying_client::rate_limit::RateLimited` from the application's own
`limit.add(...)` MUST convert into the same `Denied`.

## Pacing

r[item.axum.route-pacing]
`RoutePacing::new(pacing)` MUST be a tower layer that paces the HTTP
requests it wraps as `paced` does (`item.relying-client.pacing.concurrent`),
from when it is called to when the answer it wraps is ready, whatever that
answer is: an allow, a `Denied`, a rate limit, the handler's error or an
extractor's rejection (`item.relying-client.pacing.errors`). Applied to a
`Router`, it MUST pace the router's own answers, such as 404 and 405, too.
It MUST NOT pace websocket upgrade requests.

r[item.axum.route-pacing.nested]
Every `RoutePacing` around a request MUST wait on its own, so the answer
waits for the longest of them.

r[item.axum.route-pacing.order]
A `RoutePacing` that meets a request a `RoutePolicy` has already evaluated
MUST answer as a misconfiguration (`item.axum.misconfiguration`): it would
start after the decision, so a denial would answer sooner than an allow.

## Injected tokens

r[item.axum.injected-tokens]
The crate MUST offer extractors for the token verified for the request:
`CurrentToken` (any admitted kind), `OptionalToken` (`None` without a
token), `IdentityToken` (only `identity` tokens) and `TenantToken` (only
`tenant` tokens). They MUST read the route policy's evaluation, so no
handler receives a token its route's policy hasn't allowed, and MUST fail
closed on a route without a `RoutePolicy`. On a public route,
`OptionalToken` MUST verify a presented token without a decision and run
the hooks, and refuse an invalid one.

r[item.axum.injected-kinds]
An extractor whose accepted token kinds don't include every kind the
route's policy admits (its token kinds, or only `tenant` when unset), and
any extractor other than `OptionalToken` on a public route, MUST fail
closed (`item.axum.misconfiguration`) whatever the request's token.

## Validation

r[item.axum.validation]
axum doesn't let a layer see the route it is applied to, nor list an
application's routes, so checks happen in two places. Building a
`RoutePolicy` MUST refuse, with `RoutePolicyError`, what its route
policies alone show: a public policy merged with constraints,
contradictions (`item.relying.policy.merge-contradiction`), `admit_flags`
outside the route's own policy, an empty allowed set
(`item.relying.policy.check`) and attached rate-limit templates the policy
can't render. What depends on the matched route or the configuration MUST
be checked on each request it concerns
(`item.axum.misconfiguration`).

r[item.axum.misconfiguration]
A request that meets a route the application set up wrongly MUST fail
closed with 500 and an error logged naming the problem, before any handler
runs where the problem is found before one: no `Konklav` installed, a
second `RoutePolicy`, a scope kind with neither a resolver nor a path
parameter of its name, a rate-limit template the request can't render, an
extractor without a `RoutePolicy` or not matching its policy
(`item.axum.injected-kinds`), a request without a peer address for a
client address, and a `RoutePacing` inside a `RoutePolicy`
(`item.axum.route-pacing.order`).

r[item.axum.describe]
`RoutePolicy::describe` MUST give the route's merged policy as
`konklav-fastapi` publishes it in `x-konklav-policy`
(`item.py-fastapi.openapi`), for an application that publishes OpenAPI
itself.
