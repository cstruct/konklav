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
  5. Make one `decide_accepted_typed` call for the accepted request.
- Outcomes as exceptions (`konklav_fastapi.errors`): `Unauthenticated`
  (401), `Forbidden` (403), `StepUpRequired` (401) and
  `KonklavUnavailable` (503), with a default handler that the application
  can replace.
- Injected tokens: `CurrentToken`, `OptionalToken`, `IdentityToken`,
  `TenantToken`.
- Startup validation over every HTTP and websocket route, and
  `x-konklav-policy` in OpenAPI.

Out of scope:

- Deciding anything: the relying core decides, through `RelyingClient`.
- The meaning of a relying system's resources: scope resolvers map them to
  scopes.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-py` (`konklav-relying`) | Required at exactly this package's version; provides `Policy`, `RelyingClient` (`accept_request`, `decide_accepted_typed`) and the typed results |
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
(`relying.verify.accepted-presentation`).

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
