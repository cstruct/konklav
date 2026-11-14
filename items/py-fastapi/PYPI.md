# konklav-fastapi

[Konklav](https://github.com/cstruct/konklav) route policies for FastAPI.

Declare an operation's requirements as a `RoutePolicy` on routes, routers
and `include_router`; install `KonklavRoutes` once with your started
`RelyingClient` from [`konklav-relying`](https://pypi.org/project/konklav-relying/),
and every request is decided by the relying core with one call.

```python
from fastapi import APIRouter
from konklav_fastapi import KonklavRoutes, RoutePolicy, TenantToken

router = APIRouter(dependencies=[RoutePolicy(tenant_actions={"project:read"})])


@router.get("/projects/{project}", dependencies=[RoutePolicy(scope_actions={"project": {"document:read"}})])
async def read_project(project: str, token: TenantToken) -> dict[str, str]:
    return {"project": project, "subject": token.sub}
```

A handler that decides more than its route policy states injects
`RequestDecider`. Its decisions reuse the route's verified presentation and
are made with the route decision's route authority, so a route requiring
`user:manage_data`, which the catalog says vouches for `user:write`, lets
the handler's `user:write` decision allow, while a route requiring
`user:write` still forbids a subject who doesn't hold it:

```python
from konklav_fastapi import RequestDecider


@router.post("/users/{user}/data", dependencies=[RoutePolicy(tenant_actions={"user:manage_data"})])
async def manage_data(user: str, decider: RequestDecider) -> dict[str, bool]:
    decision = await decider.decide_typed({"tenant": ["user:write"]})
    return {"write": decision.allowed}
```

Startup validation refuses routes without a policy, policies that can't be
decided, and token dependencies the policy doesn't match. Each operation's
merged policy is published in OpenAPI as `x-konklav-policy`.

`RoutePacing(pacing)` paces routes whose response time could reveal
whether a record exists, such as invites and password resets: declared
before the `RoutePolicy`, it answers no sooner than `floor ± jitter`, also
for denials and errors. `PacingMiddleware` paces every answer for chosen
paths, including those FastAPI gives before any dependency runs:

```python
from datetime import timedelta

from konklav_relying import Pacing
from konklav_fastapi import PacingMiddleware, RoutePacing

pacing = Pacing(floor=timedelta(milliseconds=800), jitter=timedelta(milliseconds=200))
router = APIRouter(dependencies=[RoutePacing(pacing), RoutePolicy(tenant_actions={"member:invite"})])
app.add_middleware(PacingMiddleware, pacing=pacing, paths={"/password-resets"})
```

`RouteRateLimit(limit, "{token:sub}/{path:project}")` limits routes with a
`konklav_relying.RateLimit`, keyed by path parameters, token claims or
`{client:address}` (honouring `trusted_proxies`). Refused requests, and
`RateLimited` raised in handlers, are answered with 429 and `Retry-After`.

## Versions

The package has the same version as the Konklav server it was released
with, and requires `konklav-relying` of that version. It is supported only
against a server of the same version.
