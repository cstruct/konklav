# konklav-py-fastapi (`konklav-fastapi` on PyPI)

The FastAPI integration of the Python relying binding: a pure-Python
package that lets a relying system declare route policies on FastAPI
routes and routers, and decides each request with the relying core.

It is the FastAPI side of `konklav_relying.policy.Policy`
([`items/py`](../py/README.md)), which stays framework-free. Each release
publishes it to PyPI with the other Python packages.

## Responsibilities

- `RoutePolicy`: a `Policy` that is also a FastAPI `Depends`, declared on
  routes, routers, `include_router` and the application. Every
  `RoutePolicy` shares one dependency callable, so FastAPI's per-request
  cache evaluates a route once.
- `KonklavRoutes`: the application's configuration, installed once. It holds
  the started `RelyingClient`, a scope resolver per scope kind, an optional
  route-tenant resolver, hooks run on every verified token, an optional
  cookie hook and the public URL behind a proxy.
- Evaluation, per request:
  1. Merge the route's policies, outermost first, admitting flags only from
     the route's own.
  2. Take the token from the `Authorization` header, the cookie hook or, for
     websockets, the `token` query parameter.
  3. Verify the token, its session and its DPoP proof once
     (`accept_request`), then run the hooks.
  4. Deny a route tenant that isn't the token's, and resolve the scope ids.
  5. Make the route decision: one `decide_accepted_typed` call for the
     accepted request, with `route=True`.
  6. Release the accepted presentation once the request is answered,
     after the response is sent (streaming included), or right away when
     the route refuses the request or its decision fails.
- `RequestDecider`: an injected `Decider` with which a handler decides
  further requirements of its request (`decide`, `decide_typed`), made
  with the route decision's route authority, until the request is
  answered.
- Outcomes as exceptions (`konklav_fastapi.errors`): `Unauthenticated`
  (401), `Forbidden` (403), `StepUpRequired` (401) and
  `KonklavUnavailable` (503), with a default handler that the application
  can replace.
- Rate limits (`konklav_fastapi.rate_limits`): `RouteRateLimit(limit, key)`
  adds one event per request to a `konklav_relying.RateLimit`, for a key
  template such as `"{token:sub}/{path:project}"` or the key a dependency
  returns. Startup validation refuses templates a route can't render.
  `install` answers `RateLimited`, from it or from the application's own
  `limit.add(...)`, with 429 and a jittered `Retry-After`, or closes
  websockets with 1013.
- Client addresses: `KonklavRoutes.client_address`, which reads
  `X-Forwarded-For` only from `trusted_proxies`.
- Injected tokens: `CurrentToken`, `OptionalToken`, `IdentityToken`,
  `TenantToken`, and `RequestDecider`, refused on public routes.
- Startup validation over every HTTP and websocket route, and
  `x-konklav-policy` in OpenAPI.
- Pacing: `RoutePacing`, a dependency that paces the routes it is
  declared on, and `PacingMiddleware`, which paces every answer for chosen
  paths (`konklav_relying.pacing`).

Out of scope:

- Deciding anything: the relying core decides, through `RelyingClient`.
- The meaning of a relying system's resources: scope resolvers map them to
  scopes.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-py` (`konklav-relying`) | Required at exactly this package's version; provides `Policy`, `RelyingClient` (`accept_request`, `decide_accepted`, `decide_accepted_typed`, `release_accepted`), the typed results and `Pacing` |
| `konklav-py-control-plane` | Used by the integration tests only, to set up a server |
| `konklav-server` | Decides through the relying client; only the same version is supported |

## Usage

```python
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.requests import HTTPConnection
from konklav_relying import AccessToken, RelyingClient
from konklav_fastapi import KonklavRoutes, ResolvedScope, RoutePolicy, TenantToken

router = APIRouter(dependencies=[RoutePolicy(tenant_actions={"project:read"})])


@router.get(
    "/projects/{project}/documents/{document}",
    dependencies=[RoutePolicy(scope_actions={"document": {"document:read"}}, admit_flags={"personal_only"})],
)
async def read_document(project: str, document: str, token: TenantToken) -> dict[str, str]:
    return {"document": document, "subject": token.sub}


async def document_scope(connection: HTTPConnection, claims: AccessToken) -> ResolvedScope:
    # A document is a `project_document` or a `personal_document`; only the
    # application knows which, so the resolver names the kind.
    document = connection.path_params["document"]
    return ResolvedScope(id=document, kind=await kind_of(document))


routes = KonklavRoutes(scope_resolvers={"document": document_scope})


@asynccontextmanager
async def lifespan(app: FastAPI):
    routes.client = RelyingClient(relying_url=..., subject_url=..., key_id=..., secret=..., issuer=..., audiences=...)
    await routes.client.start()
    yield
    await routes.client.stop()


app = FastAPI(lifespan=lifespan)
app.include_router(router)
routes.install(app)
```

### Merging

A route's policies merge as `Policy.merge` does: the application's, then
each including router's from the outermost in, the route's router's, and the
route's. Actions accumulate, allowed sets intersect and the strictest
step-up wins. `RoutePolicy.override(...)` replaces only the fields it sets,
and `RoutePolicy.public()` admits anyone without reading a token.

Admitted flags are the exception. They intersect when merged, so only the
route's own `RoutePolicy` (in its decorator) can admit a restrictive flag,
and startup validation refuses `admit_flags` on any other layer.

### A resource of several kinds

A policy names each scope kind it needs, and every kind it names is required.
When a route takes a resource that may be of several kinds, declare one kind
in the policy and let its resolver return a `ResolvedScope` with the
resource's actual kind. The application knows its resource's kind, and
Konklav decides a registered scope only from its record under that kind.
Asking for any of several kinds would instead mean one decision per kind.

### Route tenants

Tenant actions, tenant facts and scopes without an owner tenant always mean
the token's tenant. If routes also address a tenant themselves, such as
`/tenants/{tenant}/...`, set `route_tenant` to return it: a request whose
route tenant isn't the token's `tid` is denied with `token_tenant` before
any decision.

### Audiences

A `RelyingClient` may accept tokens for several audiences, such as
Konklav's own for services and an OIDC client's for people. Set
`audiences` on a `RoutePolicy` to admit only some of them on its routes.
They intersect when merged, an override replaces them, and a token for
another audience is denied with `token_audience` right after it verifies,
before the hooks and the decision:

```python
people = APIRouter(dependencies=[RoutePolicy(audiences={"app"})])
```

### Verification and DPoP

The relying core answers each DPoP proof once and refuses it as a replay
afterwards. So the package doesn't verify with `verify_request` and then
decide with `decide_request`. It accepts the request with `accept_request`,
which verifies the token, its session and its proof, and returns the
verified token with a handle. Hooks, the route tenant and the scope
resolvers only ever see that verified token. One `decide_accepted_typed`
call then decides for the handle, rechecking the session but not the proof
(`relying.verify.accepted-presentation`). It is the request's route
decision.

### Deciding inside a handler

A handler that needs to decide more than its route policy states injects
`RequestDecider`. Its decisions are for the same accepted presentation,
so they need no second proof, and are made with the route decision's
route authority (`relying.verify.route-authority`): a route requiring
`user:manage_data`, whose catalog entry vouches for `user:write`, lets the
handler's `user:write` decision allow, while a route requiring
`user:write` itself still forbids a subject who doesn't hold it.

```python
from konklav_fastapi import RequestDecider, RoutePolicy


@router.post("/users/{user}/data", dependencies=[RoutePolicy(tenant_actions={"user:manage_data"})])
async def manage_data(user: str, decider: RequestDecider) -> dict[str, bool]:
    decision = await decider.decide_typed({"tenant": ["user:write"]})
    return {"write": decision.allowed}
```

A handler's decisions vouch for nothing further. The presentation is
released once the request is answered, after which the decider denies
with `invalid_token`.

### Pacing

An endpoint that invites an address or starts a password reset should take
as long for an address that exists as for one that doesn't. `RoutePacing`
paces the routes it is declared on, with a `Pacing` from `konklav-relying`
(which also has `fake_uuid7`, for the id such an answer carries):

```python
from datetime import timedelta

from konklav_relying import Pacing, fake_uuid7
from konklav_fastapi import RoutePacing, RoutePolicy

pacing = Pacing(floor=timedelta(milliseconds=800), jitter=timedelta(milliseconds=200))
invites = APIRouter(dependencies=[RoutePacing(pacing), RoutePolicy(tenant_actions={"member:invite"})])


@invites.post("/invites")
async def invite(body: Invite) -> Invited:
    member = await find_member(body.address)
    return Invited(id=await send_invite(member) if member else fake_uuid7())
```

- It is a `yield` dependency with `scope="function"`, which FastAPI
  supports in every version this package does. Its wait starts when FastAPI
  resolves it and ends after the handler, also when the handler or a later
  dependency raises (`KonklavDenied`, `RateLimited`, `HTTPException`, a
  parameter that doesn't validate), and before the response is sent.
- Declare it on a route, a router, `include_router` or the application, and
  before the `RoutePolicy` and any `RouteRateLimit`. FastAPI resolves
  dependencies in order, so one resolved after anything that evaluates the
  policy (a `RoutePolicy`, or a rate limit keyed by a token claim) would
  start after the decision, and a denial would answer sooner than an allow.
  Startup validation refuses that.
- Each `RoutePacing` waits on its own, so a route under several waits for
  the longest.
- Websocket connections aren't paced, and cancellation isn't either (see
  [`konklav-relying`](../py/README.md#pacing-and-fake-ids)).

What a dependency can't pace: FastAPI answers a body it can't parse
(malformed JSON, 422, or an unreadable form, 400) before it resolves any
dependency, and an unknown path (404) or method (405), or anything
middleware answers, never reaches one. Parameters that don't validate are
fine: FastAPI resolves dependencies first and answers 422 after them.

`PacingMiddleware` covers every answer for the paths it is given, including
those and unhandled errors (500), by holding back the start of the
response until the wait is done. Paths are compared exactly with
`request.url.path`:

```python
app.add_middleware(PacingMiddleware, pacing=pacing, paths={"/invites", "/password-resets"})
```

`konklav-axum` paces axum routes with its `RoutePacing` layer
([`items/axum`](../axum/README.md#pacing)). A layer wraps its route's
whole answer, so it needs no counterpart of `PacingMiddleware`.

### Rate limits

```python
login_rate_limit = RateLimit("login", [RateLimitWindow(size=5, period=timedelta(minutes=1))])
exports_rate_limit = RateLimit("export", [RateLimitWindow(size=10, period=timedelta(hours=1))])


@app.post("/login", dependencies=[RoutePolicy.public(), RouteRateLimit(login_rate_limit, "{client:address}")])
async def login(form: LoginForm) -> ...:
    await login_rate_limit.add(form.email)  # a second limit, in code


@router.post("/projects/{project}/export", dependencies=[RouteRateLimit(exports_rate_limit, "{token:sub}/{path:project}")])
async def export(project: str) -> ...: ...
```

A key template is literal text and fields, with `{{` and `}}` for literal
braces:

| Field | Value |
|---|---|
| `{path:<name>}` | The path parameter `<name>` |
| `{token:sub}`, `{token:sid}`, `{token:knd}` | A claim of the token the route's policy verified |
| `{token:tid}` | The tenant, on routes that admit only tenant tokens |
| `{client:address}` | `KonklavRoutes.client_address` |

Startup validation refuses a template that names a path parameter the route
doesn't have, a token claim on a public route, or `tid` where other token
kinds are admitted. The parts are encoded so that different values never
render the same key.

Behind a load balancer, set `trusted_proxies` (addresses or networks) on
`KonklavRoutes`. Otherwise `{client:address}` is the proxy's address, and
every client shares one limit. `X-Forwarded-For` is read only from trusted
proxies, last untrusted hop first, as the Konklav server does.

For anything else, `key` can be a dependency returning `str` or `bytes`. It
can depend on others, such as `TenantToken`.

## Testing

```sh
mise run py-fastapi:test
```

This builds `konklav-server` and `test-server`, and runs the unit tests and
the integration tests. The integration tests use a real `RelyingClient`
against a server on a fresh database, so they need the development Postgres
(`mise run db:up`). Without `KONKLAV_TEST_SERVER`, they are skipped.

CI also runs the unit tests against the lowest FastAPI version the package
supports. Locally:

```sh
uv run --with fastapi==0.143.0 pytest -q tests --ignore=tests/integration
```

The lockfile holds the highest supported version. When you widen the range
in `pyproject.toml`, relock so that it still does.

## Traceability

- Spec: [`docs/spec/software-items/py-fastapi.md`](../../docs/spec/software-items/py-fastapi.md)
  (`item.py-fastapi.*`), building on `item.py.policy.*`.
- FastAPI internals it reads: [`src/konklav_fastapi/_routing.py`](src/konklav_fastapi/_routing.py).
