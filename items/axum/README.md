# konklav-axum

The axum integration of the native Rust host binding, published on
crates.io as `konklav-axum`. It lets a relying system served by axum
declare route policies on its routes and rate limits on them, and decides
each request with the relying core through `konklav-relying-client`.

It is the Rust counterpart of [`konklav-fastapi`](../py-fastapi/README.md):
the same evaluation, the same answers (statuses, bodies, `WWW-Authenticate`
challenges), the same extractors for the verified token and the same
rate-limit key templates, in axum's terms (layers, extractors,
`IntoResponse`).

## Responsibilities

- `RouterPolicy` and `RoutePolicy`: the route policies of the routers around
  a route, nested outermost first, and the layer each route carries with
  its complete, merged route policy. Merging is
  `konklav_relying::policy::Policy::merge`; only the route's own route
  policy can admit restrictive flags.
- `Konklav`: the application's configuration, installed once on the router
  (`.layer(konklav.layer())`). It holds the relying host (a started
  `RelyingClient`), a scope resolver per scope kind, an optional
  route-tenant resolver, hooks run on every verified token, an optional
  cookie hook, the public URL behind a proxy, trusted proxies and an
  optional answer for every `Denied`.
- Evaluation, once per request, before the handler:
  1. Take the token from the `Authorization` header, the cookie hook or, for
     websocket upgrades, the `token` query parameter.
  2. Accept the presentation once (`RelyingClient::accept_request`), which
     verifies the token, its session and its DPoP proof against the public
     URL, then run the hooks.
  3. Deny a route tenant that isn't the token's, and resolve the scopes from
     resolvers or path parameters.
  4. Make one `decide_accepted` call for the route's requirements.
  5. Hand the handler a `RequestDecider` for further decisions with the
     same presentation, and release the presentation once the handler has
     answered.
- Outcomes as `Denied`, an `IntoResponse` error: `Unauthenticated` (401),
  `Forbidden` (403), `StepUpRequired` (401, RFC 9470), `Unavailable` (503)
  and `RateLimited` (429).
- Extractors: `CurrentToken`, `OptionalToken`, `IdentityToken`,
  `TenantToken`, `RequestDecider` (`item.axum.request-decider`), and
  `ClientAddress`.
- `RoutePacing`: a layer pacing the answers it wraps
  (`konklav_relying_client::pacing`, re-exported as `Pacing` and `paced`).
- Rate limits: `RouteRateLimit(limit, key)` over
  `konklav_relying_client::rate_limit::RateLimit`, with a key template or a
  key function, attached to a `RoutePolicy` or as a layer of its own.
- `RelyingHost`: the trait it decides through, implemented for
  `RelyingClient`, so tests and applications can stand in for the client.

Out of scope:

- Deciding anything: the relying core decides, through `RelyingClient`.
- The meaning of a relying system's resources: scope resolvers map them to
  scopes.
- OpenAPI: axum has none of its own. `RoutePolicy::describe()` gives what
  `konklav-fastapi` publishes as `x-konklav-policy`, for an application
  that publishes OpenAPI itself.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-relying` | Required at exactly this crate's version; provides `policy::Policy` (merging, requirements) and every decision rule |
| `konklav-relying-client` | Required at exactly this crate's version; `RelyingClient` (`accept_request`, `decide_accepted`, `verify_request`) and `rate_limit::RateLimit` |
| `konklav-authz`, `konklav-token`, `konklav-core` | Requirements, decisions, claims and ids |
| `konklav-server` | Used by the end-to-end test only; decides through the relying client, and only the same version is supported |
| `konklav-py-fastapi` | Its Python counterpart: answers alike and renders the same rate-limit keys |

## Usage

```rust
use std::net::SocketAddr;

use axum::{Router, routing::{get, post}};
use axum::http::request::Parts;
use konklav_axum::{
    Konklav, Policy, ResolvedScope, RoutePolicy, RouteRateLimit, RouterPolicy, TenantToken,
    path_param,
};
use konklav_relying_client::RelyingClient;
use konklav_relying_client::rate_limit::{RateLimit, RateLimitConfig, RateLimitWindow};

async fn read_document(token: TenantToken) -> String {
    token.sub.to_string()
}

fn app(client: RelyingClient) -> Result<Router, Box<dyn std::error::Error>> {
    let konklav = Konklav::builder(client)
        // A document is a `project_document` or a `personal_document`; only
        // the application knows which, so the resolver names the kind.
        .scope_resolver("document", |parts: &Parts, _token| {
            let document = path_param(parts, "document").unwrap_or_default().to_owned();
            async move { Ok(ResolvedScope::new(document).of_kind("project_document")) }
        })
        .trusted_proxies(["10.0.0.0/8"])
        .build()?;

    let projects = RouterPolicy::new(Policy::new().tenant_actions(["project:read"]));
    let login = RateLimit::new(RateLimitConfig::new(
        "login",
        vec![RateLimitWindow { size: 5, period_ms: 60_000 }],
    ))?;

    Ok(Router::new()
        .route(
            "/projects/{project}/documents/{document}",
            get(read_document).route_layer(projects.route(
                &Policy::new()
                    .scope_actions("document", ["document:read"])
                    .admit_flags(["personal_only"]),
            )?),
        )
        .route(
            "/login",
            post(|| async { "..." }).route_layer(
                RoutePolicy::public().rate_limit(RouteRateLimit::new(login, "{client:address}")?)?,
            ),
        )
        .layer(konklav.layer()))
}

// Serve with connect info, so client addresses are known:
// axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
```

`RelyingClient` must be started (`client.start()`) before serving.

### Merging

A route's route policy is the merge of `RouterPolicy::new(...)`, each
`.nest(...)` from the outermost in, and the route's own, given to
`.route(...)`. Actions accumulate, allowed sets intersect and the strictest
step-up wins. `Policy::overriding()` replaces only the fields it sets, and
`RoutePolicy::public()` (or `Policy::override_public()` inside routers)
admits anyone without reading a token. `.route(...)` refuses a router
policy that sets `admit_flags`, so a router can never admit a restrictive
flag for every route under it.

Router policies are values rather than layers on a `Router`: an axum layer
can't tell whether a layer inside it will evaluate, so stacked router
layers would either decide before the route's own policy is known or let a
handler run with nothing evaluated. Each route instead carries one
`RoutePolicy`, merged when it is built.

### What is checked when

axum doesn't let a layer see its route, nor list an application's routes,
so:

- Building a `RoutePolicy` (at startup) refuses what its route policies
  show: a public policy merged with constraints, contradicting tenant facts,
  `admit_flags` outside the route's own policy, an empty allowed set, and
  attached rate-limit templates the policy can't render (a token claim on a
  public route, `tid` where other token kinds are admitted).
- Each request refuses, with 500 and an error log, what depends on the
  matched route or the configuration: no `Konklav` installed, a second
  `RoutePolicy` on one route, a scope kind with neither a resolver nor a
  path parameter of its name, a template naming a missing path parameter or
  a token no policy verified, an extractor that doesn't match its route's
  policy (or a route without one), and a request without a peer address for
  `{client:address}`.

These fail closed, before the handler, the first time a request reaches the
route; test each route once to find them.

### Verification and DPoP

The relying core answers each DPoP proof once and refuses it as a replay
afterwards. So evaluation accepts the request once
(`RelyingClient::accept_request`), which returns the verified claims with a
handle; hooks, the route tenant and the scope resolvers only ever see those
claims, and one `decide_accepted` call decides for the handle
(`relying.verify.accepted-presentation`). A handler that decides more, such
as a GraphQL server per field, extracts `RequestDecider` and decides with
the same handle, without the proof again; the layer releases the handle
once the handler has answered, after which it decides nothing. The URL proofs are checked against
is the `public_url` hook's, else the request's own scheme and authority,
else `http://` and its `Host` header: set `public_url` behind TLS or a proxy.

### Answers

`Denied` answers as `konklav-fastapi` does: `{"error": {"code": ...}}` with
the deny reason (`forbidden`) or the step-up requirement (`step_up`), and
`WWW-Authenticate` challenges in the token's scheme. Replace every answer
with `KonklavBuilder::respond_with`. Websocket upgrade requests that are
denied or rate limited are answered with the HTTP status, refusing the
upgrade: the layer runs before it, so there is no socket to close.

### Rate limits

A key template is literal text and fields, with `{{` and `}}` for literal
braces:

| Field | Value |
|---|---|
| `{path:<name>}` | The path parameter `<name>` |
| `{token:sub}`, `{token:sid}`, `{token:knd}` | A claim of the token the route's policy verified |
| `{token:tid}` | The tenant, on routes that admit only tenant tokens |
| `{client:address}` | `Konklav::client_address` |

The parts are encoded as a JSON array, so that different values never
render the same key, and exactly as `konklav-fastapi` encodes them, so a
Rust and a Python service sharing a rate-limit store share the limit.

Attach a limit to a route's policy with `RoutePolicy::rate_limit` to count
the requests the policy allows, with its verified token. A `RouteRateLimit`
is also a layer of its own; applied with `route_layer` after the
`RoutePolicy` it runs before it, which suits keys without a token such as
`{client:address}`. `RouteRateLimit::keyed` takes an async function of the
request's parts and the verified token instead. In a handler, call
`limit.add(key).await?` and return `Denied`.

To share limits through a rate-limit store, depend on
`konklav-relying-client` with its `redis` feature and build the limit with
`RateLimit::with_redis`; this crate takes any `RateLimit`.

Behind a load balancer, set `trusted_proxies` (addresses or CIDR networks).
Otherwise `{client:address}` is the proxy's address, and every client
shares one limit. `X-Forwarded-For` is read only from trusted proxies, last
untrusted hop first, as the Konklav server does.

### Pacing

An endpoint whose answer could reveal whether a record exists, such as
inviting an address or starting a password reset, often does more work for
a known record than for an unknown one. `RoutePacing::new(pacing)` answers
no sooner than a wait drawn from `floor ± jitter`, run together with the
route, so its response time is the floor (plus jitter) unless the work
takes longer:

```rust
use std::time::Duration;

use axum::{Router, routing::post};
use konklav_axum::{Pacing, Policy, RoutePacing, RouterPolicy};
use konklav_relying_client::fake_ids::fake_uuid7;

fn invites(api: &RouterPolicy) -> Result<Router, Box<dyn std::error::Error>> {
    let pacing = Pacing::new(Duration::from_millis(800), Duration::from_millis(200));
    Ok(Router::new().route(
        "/invites",
        // A known address gets the new invite's id; an unknown one gets a
        // fake id, just as fresh, and an answer just as late.
        post(|| async { fake_uuid7().to_string() })
            .route_layer(api.route(&Policy::new().tenant_actions(["member:invite"]))?)
            .route_layer(RoutePacing::new(pacing)),
    ))
}
```

A layer wraps its route's whole answer, so the wait also holds back every
`Denied`, rate limit, handler error and extractor rejection (an unparsable
body's 400 or 422). Applied to a `Router` with `.layer`, a `RoutePacing`
paces its 404 and 405 answers too, which `konklav-fastapi` needs
`PacingMiddleware` for. Each `RoutePacing` waits on its own, so a route
under several waits for the longest.

- Apply it with `route_layer` after the route's `RoutePolicy`, so it wraps
  the policy. Inside the policy it would start after the decision, and a
  denial would answer sooner than an allow; it answers 500 there instead.
- Cancellation isn't paced: when the client goes away, the wait is dropped
  with the request. A panic isn't paced either, unless a panic-catching
  layer inside the `RoutePacing` turns it into a 500.
- Websocket upgrade requests aren't paced.
- In tests, use `Pacing::NONE`.

To pace part of a handler, call `paced(pacing, work).await`. Answer with a
fake id (`konklav_relying_client::fake_ids`) where the real answer would
carry an id that wasn't created: `fake_uuid7()` claims now, and
`fake_uuid7_within(window)` claims a millisecond from a past window, for
something that would already exist. A fake id helps only in an answer that
is also paced.

## Testing

```sh
mise run db:up
cargo test -p konklav-axum
```

- Unit tests (`tests/routes.rs`, `tests/rate_limits.rs`, `tests/pacing.rs`
  and the crate's own) use a fake `RelyingHost`: merging and its refusals, every outcome,
  token extraction, hooks, route tenants, scope resolvers, extractors and
  their kinds, misconfigurations, rate limits, key templates, client
  addresses and pacing.
- The end-to-end test (`tests/end_to_end.rs`) serves an axum application
  deciding through a real `RelyingClient` against a Konklav server on a
  fresh database, so it needs the development Postgres.

## Traceability

- Spec: [`docs/spec/software-items/axum.md`](../../docs/spec/software-items/axum.md)
  (`item.axum.*`), building on `item.relying.policy.*` in
  [`relying.md`](../../docs/spec/software-items/relying.md).
- Plan and design decisions: [`.agents/plans/konklav-axum.md`](../../.agents/plans/konklav-axum.md).
