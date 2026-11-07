# Python FastAPI Integration Software Item

Stable implementation contracts owned by `konklav-py-fastapi`, the FastAPI
integration of the Python relying binding's route policies, published as
`konklav-fastapi` and imported as `konklav_fastapi`.

It builds on `konklav_relying.policy.Policy` (`item.py.policy.*`) and only
translates between it and FastAPI: every decision is the relying core's.

## Packaging

r[item.py-fastapi.pure-python]
The package MUST contain no native code. It MUST require `konklav-relying`
at exactly its own version, and `fastapi` within a stated range of
versions.

r[item.py-fastapi.same-version]
The package MUST carry the version of the Konklav release it was built
with, like `konklav-relying` (`item.py-control-plane.same-version`).

r[item.py-fastapi.fastapi-range]
The package MUST state the FastAPI versions it supports as a bounded range
in its requirements, since it reads how FastAPI keeps the routes of included
routers. CI MUST run its tests against the lowest and the highest version of
that range.

## Route policies

r[item.py-fastapi.route-policy]
`RoutePolicy` MUST be both a `konklav_relying.policy.Policy` and a FastAPI
`Depends`, so a relying system declares it in the `dependencies` of a route,
of an `APIRouter`, of `include_router` or of the application.
`RoutePolicy.public()` and `RoutePolicy.override(...)` MUST return
`RoutePolicy`s.

r[item.py-fastapi.shared-dependency]
Every `RoutePolicy` MUST share one dependency callable, so that FastAPI's
per-request dependency cache evaluates a route's policy once, however many
layers declare one.

r[item.py-fastapi.merge-order]
A route's policy MUST be the `Policy.merge` (`item.py.policy.merge`) of the
`RoutePolicy`s FastAPI combines for it, in FastAPI's order: the
application's, then each including router's and `include_router`'s from the
outermost in, then those of the route's own router, then the route's. This
MUST hold for HTTP and websocket routes, and per inclusion when one router
is included more than once.

r[item.py-fastapi.admit-flags-operation]
Admitted restrictive flags intersect when policies merge
(`item.py.policy.merge`), so admitting a flag is the operation's decision
alone. A route's admitted flags MUST be taken only from the `RoutePolicy`s
declared on the route itself (in its decorator or `add_api_route`), never
from its router, an including router or the application. Startup
validation (`item.py-fastapi.validation`) MUST refuse a `RoutePolicy` on any
of those layers that sets `admit_flags`, so a router can never admit a
restrictive flag for every route under it.

r[item.py-fastapi.audiences]
A `RoutePolicy` MAY set `audiences`, the token audiences its routes accept
among those the `RelyingClient` accepts (`relying.verify.audiences`).
Audiences MUST intersect when policies merge, and an override that sets
them MUST replace them. A route that isn't public and whose merged policy
sets audiences MUST deny a token whose `aud` isn't one of them, after
verifying it and before anything else reads it, with the deny reason
`token_audience`.

r[item.py-fastapi.public]
A route whose merged policy is public (`item.py.policy.public`) MUST be
served without reading or verifying a token, and without a decision.

## Evaluation

r[item.py-fastapi.token-extraction]
The token MUST be taken, in this order, from the `Authorization` header
(with the `DPoP` header, as `decide_request` takes them), from the cookie
hook if the relying system configured one, or, for websocket connections
only, from the `token` query parameter, which browsers need since they
can't set headers on websockets. A token from the cookie hook or the query
parameter MUST be presented with the `DPoP` scheme when a `DPoP` header is
present, and as a bearer token otherwise. The query parameter MUST NOT be
read for HTTP requests.

r[item.py-fastapi.verify-then-decide]
A route that isn't public MUST verify the request's token, its session and
any DPoP proof before anything else reads it, by accepting the presentation
with `accept_request` (`item.py.accepted-request`), with the presented
`Authorization` and `DPoP` values, the request's method (`GET` for a
websocket) and its URL as the client addressed it. Only then, in this order,
MUST it check the token's audience (`item.py-fastapi.audiences`), run the
hooks (`item.py-fastapi.hooks`), check the route tenant
(`item.py-fastapi.token-tenant`), resolve the scope ids
(`item.py-fastapi.scope-resolvers`) and decide. So no application code sees
claims that weren't verified, and resolvers look nothing up in a tenant the
token doesn't belong to.

r[item.py-fastapi.single-decision]
A route that isn't public MUST then make exactly one decision per request,
with `decide_accepted_typed` for the accepted presentation and the
requirements of the route's merged policy (`item.py.policy.requirements`)
with the request's scope ids. The request's one DPoP proof is checked when
it is accepted, and not again (`relying.verify.accepted-presentation`).

r[item.py-fastapi.scope-resolvers]
The relying system MUST be able to configure one scope resolver per scope
kind, an async callable taking the connection and the verified token. A
scope kind without a resolver MUST be resolved from the path parameter of
the kind's name. A resolver MUST be able to return a `ResolvedScope` that
names, besides the id, the scope kind the requirement uses in the decision
and the scope's owner tenant (`authz.share.requirements`). A route that
accepts a resource of any of several scope kinds declares one kind in its
policy, whose resolver looks up which kind the resource is and returns it;
the relying system knows its resource's kind, and Konklav decides a
registered scope only from its record under that kind.

r[item.py-fastapi.token-tenant]
When the relying system configures a route-tenant resolver and it returns a
tenant for the request, a route that isn't public MUST deny, before
deciding, when that tenant isn't the token's `tid`, with the deny reason
`token_tenant` (`item.py.policy.token-tenant`).

r[item.py-fastapi.hooks]
The relying system MUST be able to configure hooks, async callables taking
the connection and the `AccessToken`, which MUST run in order on every
token this package verifies, before the route tenant, the scope resolvers
and the decision, and before any handler receives it. A hook refuses the
token by raising.

r[item.py-fastapi.outcomes]
Evaluation MUST end in one of these:

- an allow, after which the request proceeds;
- `Unauthenticated` (401) when no token is presented, it doesn't verify, or
  the decision denies with `invalid_token`; and when its DPoP proof or
  scheme is refused, as `invalid_dpop_proof` with `WWW-Authenticate: DPoP
  error="invalid_dpop_proof"` (`relying.verify.dpop-challenge`). A token
  that doesn't verify MUST be challenged in the scheme it was presented
  with, as `error="invalid_token"`, and a missing token with both `Bearer`
  and `DPoP`;
- `Forbidden` (403) for any other deny, carrying the `DenyReason`, and for
  `token_tenant` and `token_audience`;
- `StepUpRequired` (401) for a step-up demand, carrying its requirement,
  with a `WWW-Authenticate` challenge in the token's scheme as
  `error="insufficient_user_authentication"` (RFC 9470), and `max_age`
  when the requirement has one;
- `KonklavUnavailable` (503) when no decision can be reached
  (`relying.decision.fail-closed`).

Each MUST be an exception of a type the relying system can handle itself.
The default handler MUST answer HTTP requests with the status above and a
JSON body naming the code, the deny reason or the step-up requirement, and
MUST close websocket connections with code 1008 (policy violation).

## Rate limits

r[item.py-fastapi.rate-limit]
`RouteRateLimit(limit, key)` MUST be a FastAPI dependency, declarable on
routes, routers, `include_router` and the application, that adds one
event to the `konklav_relying.RateLimit` `limit` for each request. `key`
MUST be a FastAPI dependency itself, so it can depend on others, such as
the verified token.

r[item.py-fastapi.rate-limit-template]
`key` MAY instead be a template: literal text and fields `{source:name}`,
with `{{` and `}}` for literal braces. The sources MUST be `path` (a path
parameter), `token` (a claim of the verified token: `sub`, `sid`, `knd` or
`tid`) and `client` (only `client:address`, the client's address). A
malformed template, or an unknown source or claim, MUST raise `ValueError`
when the `RouteRateLimit` is created. A template's key MUST encode its parts
so that different values can't render the same key. Its token MUST be the
one the route's policy verified, not verified again.

r[item.py-fastapi.rate-limit-template-validation]
Startup validation MUST refuse a route whose rate-limit templates name a
path parameter the route doesn't have, a token claim on a public route, or
`tid` on a route whose policy admits token kinds other than `tenant`.

r[item.py-fastapi.client-address]
`KonklavRoutes.client_address(connection)` MUST answer the connection's
peer address unless the peer is one of `trusted_proxies` (addresses or
networks). Then it MUST answer the last address in `X-Forwarded-For` that
isn't a trusted proxy, or the first when all are, like the server's
`platform.server.client-address`. A connection without a peer address
MUST be refused rather than given an empty key.

r[item.py-fastapi.rate-limited]
`KonklavRoutes.install` MUST handle `konklav_relying.RateLimited`, whether
raised by `RouteRateLimit` or by the relying system's own code: HTTP
requests are answered with 429, a JSON body with the code `rate_limited`
(like the package's other codes), and a `Retry-After` header of the
retry-after time in whole seconds, rounded up, plus random jitter
(`platform.error.retry-after`); websocket connections are closed with code
1013 (try again later).

## Injected tokens

r[item.py-fastapi.injected-tokens]
The package MUST offer dependencies that inject the token verified for the
request: `CurrentToken` (any admitted kind), `OptionalToken` (`None`
without a token), `IdentityToken` (only `identity` tokens) and
`TenantToken` (only `tenant` tokens). They MUST depend on the route's
evaluation, so no handler receives a token its route's policy hasn't
allowed. On a public route, `OptionalToken` MUST verify a presented token
with `verify_request_typed` and run the hooks, and refuse an invalid one.

r[item.py-fastapi.injected-kinds]
Startup validation MUST refuse a route that injects a token dependency
whose accepted token kinds don't include every kind the route's policy
admits (its `token_kinds`, or only `tenant` when unset, Konklav's default),
and a route with a public policy that injects any token dependency other
than `OptionalToken`.

## Startup validation

r[item.py-fastapi.validation]
`KonklavRoutes` MUST validate every HTTP and websocket route of the
application when it starts, and on demand, and MUST refuse to start with an
error listing each route that fails a check. A route fails when:

- it declares no `RoutePolicy` on any layer;
- its layers merge a public policy with constraints
  (`item.py.policy.public`), or contradict each other
  (`item.py.policy.merge-contradiction`);
- a layer other than the route sets `admit_flags`
  (`item.py-fastapi.admit-flags-operation`);
- its policy needs a scope kind that has no resolver and no path parameter
  of its name;
- merging leaves an allowed set empty: token kinds, audiences or step-up's
  allowed methods;
- it injects a token dependency its policy doesn't match
  (`item.py-fastapi.injected-kinds`).

## OpenAPI

r[item.py-fastapi.openapi]
`KonklavRoutes` MUST publish each HTTP operation's merged policy in the
application's OpenAPI document as the operation extension
`x-konklav-policy`: `{"public": true}` for a public route, and otherwise
`{"public": false}` with the requirements the policy resolves to, with each
scope given by its kind and actions alone, and its `audiences` when it sets
them.
