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

Startup validation refuses routes without a policy, policies that can't be
decided, and token dependencies the policy doesn't match. Each operation's
merged policy is published in OpenAPI as `x-konklav-policy`.

## Versions

The package has the same version as the Konklav server it was released
with, and requires `konklav-relying` of that version. It is supported only
against a server of the same version.
