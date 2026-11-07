"""
Konklav route policies for FastAPI.

`RoutePolicy` is a `konklav_relying.Policy` you declare as a FastAPI
dependency on routes, routers and `include_router`. `KonklavRoutes`, which
an application installs once, holds the started `RelyingClient` and what
only the application knows: how to find each scope kind's id, the tenant a
route addresses, and hooks for every verified token.

```python
from fastapi import APIRouter, FastAPI
from konklav_fastapi import KonklavRoutes, RoutePolicy, TenantToken

router = APIRouter(dependencies=[RoutePolicy(tenant_actions={"project:read"})])


@router.get("/projects/{project}", dependencies=[RoutePolicy(scope_actions={"project": {"document:read"}})])
async def read_project(project: str, token: TenantToken) -> dict[str, str]:
    return {"project": project, "subject": token.sub}


routes = KonklavRoutes()


@asynccontextmanager
async def lifespan(app: FastAPI):
    routes.client = RelyingClient(...)
    await routes.client.start()
    yield
    await routes.client.stop()


app = FastAPI(lifespan=lifespan)
app.include_router(router)
routes.install(app)
```

Each request makes one decision with the route's merged policy; denials
raise `KonklavDenied` subclasses (`konklav_fastapi.errors`), answered with
401, 403 or 503 unless the application handles them itself.

`RouteRateLimit(limit, "{token:sub}/{path:project}")`
(`konklav_fastapi.rate_limits`) adds one event per request to a
`konklav_relying.RateLimit`, keyed by a template or a dependency; a refused
event, from it or from the application's own `limit.add(...)`, is answered
with 429.
"""

import importlib.metadata

from konklav_fastapi.errors import (
    Forbidden,
    KonklavDenied,
    KonklavUnavailable,
    RoutePolicyError,
    StepUpRequired,
    Unauthenticated,
    handle_denied,
)
from konklav_fastapi.rate_limits import RouteRateLimit, handle_rate_limited
from konklav_fastapi.routes import (
    CurrentToken,
    IdentityToken,
    KonklavRoutes,
    OptionalToken,
    ResolvedScope,
    RoutePolicy,
    RoutePolicyFields,
    RouteTenantResolver,
    ScopeResolver,
    TenantToken,
    TokenHook,
)

# r[impl item.py-fastapi.pure-python]
# r[impl item.py-fastapi.same-version]
# The release sets the version and the exact requirement on konklav-relying
# in pyproject.toml; this package is plain Python.
__version__ = importlib.metadata.version("konklav-fastapi")

__all__ = [
    "CurrentToken",
    "Forbidden",
    "IdentityToken",
    "KonklavDenied",
    "KonklavRoutes",
    "KonklavUnavailable",
    "OptionalToken",
    "ResolvedScope",
    "RoutePolicy",
    "RoutePolicyError",
    "RoutePolicyFields",
    "RouteRateLimit",
    "RouteTenantResolver",
    "ScopeResolver",
    "StepUpRequired",
    "TenantToken",
    "TokenHook",
    "Unauthenticated",
    "handle_denied",
    "handle_rate_limited",
]
