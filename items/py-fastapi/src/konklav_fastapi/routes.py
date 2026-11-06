"""
Route policies on FastAPI routes, evaluated by the relying core.

Declare a `RoutePolicy` on routes, routers or `include_router`, and install
one `KonklavRoutes` on the application:

```python
router = APIRouter(dependencies=[RoutePolicy(tenant_actions={"project:read"})])

@router.post("/projects/{project}", dependencies=[RoutePolicy(scope_actions={"project": {"project:write"}})])
async def update_project(project: str, token: TenantToken) -> ...: ...

routes = KonklavRoutes(scope_resolvers={"project": project_resolver})
routes.install(app)
```

Per request, the route's policies merge, outermost first; scope ids come
from the scope resolvers (or the path parameter of each kind's name); and
the token is verified once (`accept_request`) and one `decide_accepted_typed`
call decides.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from functools import cache
from typing import Annotated, Any, ClassVar, Literal, cast

from fastapi import FastAPI
from fastapi.params import Depends
from fastapi.requests import HTTPConnection
from fastapi.websockets import WebSocket
from konklav_relying import (
    AcceptedRequest,
    AccessToken,
    DenyReason,
    InvalidDpopProof,
    KonklavError,
    Policy,
    PolicyError,
    RelyingClient,
)

from konklav_fastapi import _routing
from konklav_fastapi.errors import (
    Forbidden,
    KonklavDenied,
    KonklavUnavailable,
    RoutePolicyError,
    StepUpRequired,
    Unauthenticated,
    handle_denied,
)

__all__ = [
    "CurrentToken",
    "IdentityToken",
    "KonklavRoutes",
    "OptionalToken",
    "ResolvedScope",
    "RouteTenantResolver",
    "RoutePolicy",
    "ScopeResolver",
    "TenantToken",
    "TokenHook",
]

TOKEN_KINDS = frozenset({"partial", "identity", "tenant", "reset_password", "invite"})
"""Every token kind Konklav issues."""
DEFAULT_TOKEN_KINDS = frozenset({"tenant"})
"""What a policy without `token_kinds` admits, as Konklav decides."""

_SCOPE_KEY = "konklav_fastapi"


@dataclass(frozen=True)
class ResolvedScope:
    """
    A scope a resolver found: its `id`, and optionally the scope `kind` the
    decision uses, when the policy's kind stands for several, and the
    scope's owner `tenant`, when it is another tenant's (then only shares
    allow it).
    """

    id: str
    kind: str | None = None
    tenant: str | None = None


type ScopeResolver = Callable[[HTTPConnection, AccessToken], Awaitable[str | ResolvedScope]]
"""Finds the id of one scope kind's scope for a request, given its verified token."""

type RouteTenantResolver = Callable[[HTTPConnection, AccessToken], Awaitable[str | None]]
"""The tenant a request addresses on its own, such as from its path, or `None`."""

type TokenHook = Callable[[HTTPConnection, AccessToken], Awaitable[None]]
"""Runs on every verified token, before handlers receive it; refuses it by raising."""


@dataclass(frozen=True)
class _Presented:
    authorization: str
    dpop: str | None
    token: str

    @property
    def scheme(self) -> str:
        """The scheme to challenge a refused token in."""
        return "DPoP" if self.authorization.partition(" ")[0].lower() == "dpop" else "Bearer"


@dataclass(frozen=True)
class _Outcome:
    public: bool
    token: AccessToken | None = None


# r[impl item.py-fastapi.shared-dependency]
async def _evaluate(connection: HTTPConnection) -> None:
    """The one dependency every `RoutePolicy` declares."""
    if _SCOPE_KEY in connection.scope:
        return
    routes = KonklavRoutes.of(connection)
    connection.scope[_SCOPE_KEY] = await routes._evaluate(connection)


# r[impl item.py-fastapi.route-policy]
@dataclass(frozen=True, kw_only=True)
class RoutePolicy(Policy, Depends):
    """
    A route policy (`konklav_relying.policy.Policy`) to declare as a FastAPI
    dependency, on a route, a router, `include_router` or the application.

    Restrictive flags are admitted only by the policies declared on the
    route itself: they intersect when merged, so a router can't admit one
    for every route under it.
    """

    # A factory: a function as a plain default would read back as a bound method.
    dependency: Callable[..., Any] | None = field(default_factory=lambda: _evaluate, init=False, repr=False)
    use_cache: bool = field(default=True, init=False, repr=False)
    scope: Literal["function", "request"] | None = field(default=None, init=False, repr=False)
    __hash__ = Policy.__hash__


# r[impl item.py-fastapi.merge-order]
# r[impl item.py-fastapi.admit-flags-operation]
@cache
def _merged(layers: tuple[RoutePolicy, ...], own: tuple[RoutePolicy, ...]) -> Policy:
    """`layers` merged outermost first, admitting only the flags `own` admits."""
    merged = Policy.merge(*layers)
    if merged.is_public:
        return merged
    operation = Policy.merge(*own)
    return replace(merged, admit_flags=None if operation.is_public else operation.admit_flags)


def _policies(dependencies: Sequence[Depends]) -> tuple[RoutePolicy, ...]:
    return tuple(dependency for dependency in dependencies if isinstance(dependency, RoutePolicy))


def _method(connection: HTTPConnection) -> str:
    # A websocket opens with a GET.
    return "GET" if isinstance(connection, WebSocket) else str(connection.scope["method"])


def _url(connection: HTTPConnection) -> str:
    url = connection.url
    if url.scheme in ("ws", "wss"):
        url = url.replace(scheme="https" if url.scheme == "wss" else "http")
    return str(url)


@dataclass(kw_only=True)
class KonklavRoutes:
    """
    What evaluating route policies needs from the application. Install it
    once with `install`; set `client` to the started `RelyingClient`, such
    as in the application's lifespan, before serving requests.
    """

    client: RelyingClient | None = None
    scope_resolvers: Mapping[str, ScopeResolver] = field(default_factory=dict)
    """One per scope kind; a kind without one takes the path parameter of its name."""
    route_tenant: RouteTenantResolver | None = None
    """When set, a route tenant that isn't the token's `tid` is denied before deciding."""
    on_verified: Sequence[TokenHook] = ()
    """Run in order on every verified token."""
    cookie: Callable[[HTTPConnection], str | None] | None = None
    """Reads the token from a cookie, for requests without an `Authorization` header."""
    public_url: Callable[[HTTPConnection], str] | None = None
    """The URL the client addressed, behind a proxy; DPoP proofs are checked against it."""

    _owners: dict[int, tuple[Any, Any]] = field(default_factory=dict, init=False, repr=False)

    STATE_ATTRIBUTE: ClassVar[str] = "konklav_routes"

    # -- installing -------------------------------------------------------

    def install(self, app: FastAPI) -> None:
        """
        Makes `app`'s routes use this configuration, validates them when the
        application starts, publishes each operation's policy in OpenAPI and
        handles `KonklavDenied` with `handle_denied`.
        """
        setattr(app.state, self.STATE_ATTRIBUTE, self)
        # Starlette types handlers per connection kind; this one takes both.
        app.add_exception_handler(KonklavDenied, cast(Any, handle_denied))

        # r[impl item.py-fastapi.validation]
        lifespan = app.router.lifespan_context

        @asynccontextmanager
        async def validated(application: Any) -> Any:
            self.validate(app)
            async with lifespan(application) as state:
                yield state

        app.router.lifespan_context = validated

        # r[impl item.py-fastapi.openapi]
        openapi = app.openapi

        def described() -> dict[str, Any]:
            if app.openapi_schema:
                return app.openapi_schema
            schema = openapi()
            for served in _routing.served_routes(app):
                operations = schema.get("paths", {}).get(served.path_format, {})
                for method in served.methods:
                    if (operation := operations.get(method.lower())) is not None:
                        try:
                            operation["x-konklav-policy"] = self.describe(served)
                        except PolicyError:
                            pass
            return schema

        cast(Any, app).openapi = described

    @classmethod
    def of(cls, connection: HTTPConnection) -> KonklavRoutes:
        """The configuration installed on the application serving `connection`."""
        routes = getattr(connection.app.state, cls.STATE_ATTRIBUTE, None)
        if not isinstance(routes, KonklavRoutes):
            raise RuntimeError("route policies need KonklavRoutes(...).install(app)")
        return routes

    # -- startup validation ---------------------------------------------

    def validate(self, app: FastAPI) -> None:
        """
        Checks every API and websocket route's policy.

        Raises:
            RoutePolicyError: listing every route that fails, and why.
        """
        self._owners = _routing.owners(app.router)
        errors = [
            f"{served.label}: {problem}"
            for served in _routing.served_routes(app)
            if (problem := self._problem(served)) is not None
        ]
        if errors:
            raise RoutePolicyError("Routes without a valid route policy:\n" + "\n".join(errors))

    def _problem(self, served: _routing.ServedRoute) -> str | None:
        layers = _policies(served.dependencies)
        own = _policies(served.own_dependencies)
        if not layers:
            return "declares no RoutePolicy; declare one, or RoutePolicy.public()"
        inherited = layers[: len(layers) - len(own)]
        if any(policy.admit_flags is not None for policy in inherited):
            return "admit_flags set outside the route; only the route's own RoutePolicy can admit flags"
        try:
            policy = _merged(layers, own)
        except PolicyError as error:
            return str(error)
        injected = [_INJECTED[call] for call in _routing.dependency_calls(served.dependant) if call in _INJECTED]
        if policy.is_public:
            for name, _ in injected:
                if name != "OptionalToken":
                    return f"injects {name}, but its policy is public; use OptionalToken"
            return None
        if policy.token_kinds == frozenset():
            return "merged policies admit no token kind"
        if policy.step_up is not None and policy.step_up.allowed_methods == frozenset():
            return "merged policies allow no step-up method"
        for kind in sorted(policy.scope_kinds):
            if kind not in self.scope_resolvers and kind not in served.path_parameters:
                return f"needs a `{kind}` scope: configure a scope resolver or add a `{kind}` path parameter"
        admitted = policy.token_kinds if policy.token_kinds is not None else DEFAULT_TOKEN_KINDS
        for name, accepted in injected:
            if not admitted <= accepted:
                return (
                    f"injects {name}, which takes {', '.join(sorted(accepted))} tokens, "
                    f"but its policy admits {', '.join(sorted(admitted))}"
                )
        return None

    # -- OpenAPI ------------------------------------------------------------

    def describe(self, served: _routing.ServedRoute) -> dict[str, Any]:
        """The route's merged policy as published in `x-konklav-policy`."""
        policy = _merged(_policies(served.dependencies), _policies(served.own_dependencies))
        if policy.is_public:
            return {"public": True}
        requirements: dict[str, Any] = dict(policy.requirements({kind: "" for kind in policy.scope_kinds}))
        if "scopes" in requirements:
            requirements["scopes"] = [
                {"kind": scope["kind"], "actions": scope["actions"]} for scope in requirements["scopes"]
            ]
        return {"public": False, **requirements}

    # -- evaluation -------------------------------------------------------

    def _policy(self, connection: HTTPConnection) -> Policy:
        found = _routing.requested(connection)
        if found is None:
            raise RoutePolicyError("route policies only apply to API and websocket routes")
        route, dependencies = found
        layers = _policies(dependencies)
        if not layers:
            raise RoutePolicyError(f"{connection.url.path} declares no RoutePolicy")
        if id(route) not in self._owners:
            # Added after startup validation, or never validated.
            self._owners = _routing.owners(connection.app.router)
        _, router = self._owners.get(id(route), (route, None))
        own = _routing.own_dependencies(route, router) if router is not None else []
        return _merged(layers, _policies(own))

    # r[impl item.py-fastapi.token-extraction]
    def _presented(self, connection: HTTPConnection) -> _Presented | None:
        dpop = connection.headers.get("dpop")
        if authorization := connection.headers.get("authorization"):
            return _Presented(authorization, dpop, authorization.partition(" ")[2].strip())
        token = self.cookie(connection) if self.cookie is not None else None
        if not token and isinstance(connection, WebSocket):
            token = connection.query_params.get("token")
        if not token:
            return None
        return _Presented(f"{'DPoP' if dpop else 'Bearer'} {token}", dpop, token)

    def _url(self, connection: HTTPConnection) -> str:
        return self.public_url(connection) if self.public_url is not None else _url(connection)

    def _client(self) -> RelyingClient:
        if self.client is None:
            # Not started yet: fail closed.
            raise KonklavUnavailable()
        return self.client

    async def _evaluate(self, connection: HTTPConnection) -> _Outcome:
        policy = self._policy(connection)
        # r[impl item.py-fastapi.public]
        if policy.is_public:
            return _Outcome(public=True)
        presented = self._presented(connection)
        if presented is None:
            raise Unauthenticated("missing_token")
        # r[impl item.py-fastapi.verify-then-decide]
        accepted = await self._accept(connection, presented)
        token = accepted.token
        await self._verified(connection, token)

        # r[impl item.py-fastapi.token-tenant]
        # r[depends item.py.policy.token-tenant]
        if self.route_tenant is not None:
            tenant = await self.route_tenant(connection, token)
            if tenant is not None and tenant != token.tid:
                raise Forbidden(DenyReason(code="token_tenant"))

        # r[impl item.py-fastapi.scope-resolvers]
        ids: dict[str, str] = {}
        owners: dict[str, str] = {}
        kinds: dict[str, str] = {}
        for kind in sorted(policy.scope_kinds):
            resolver = self.scope_resolvers.get(kind)
            if resolver is None:
                ids[kind] = str(connection.path_params[kind])
                continue
            resolved = await resolver(connection, token)
            if isinstance(resolved, str):
                resolved = ResolvedScope(resolved)
            ids[kind] = resolved.id
            if resolved.tenant is not None:
                owners[kind] = resolved.tenant
            if resolved.kind is not None:
                kinds[kind] = resolved.kind
        requirements = policy.requirements(ids, scope_tenants=owners)
        for scope in requirements.get("scopes", ()):
            scope["kind"] = kinds.get(scope["kind"], scope["kind"])

        # r[impl item.py-fastapi.single-decision]
        try:
            decision = await self._client().decide_accepted_typed(accepted, requirements)
        except KonklavError:
            raise KonklavUnavailable() from None
        match decision.decision:
            case "allow":
                return _Outcome(public=False, token=token)
            case "step_up":
                assert decision.step_up is not None
                raise StepUpRequired(decision.step_up)
            case _:
                assert decision.reason is not None
                if decision.reason.code in ("invalid_token", "invalid_dpop_proof"):
                    raise Unauthenticated(decision.reason.code, presented.scheme)
                raise Forbidden(decision.reason)

    async def _accept(self, connection: HTTPConnection, presented: _Presented) -> AcceptedRequest:
        """The presented token, its session and its DPoP proof, verified once."""
        try:
            accepted = await self._client().accept_request(
                authorization=presented.authorization,
                dpop=presented.dpop,
                method=_method(connection),
                url=self._url(connection),
            )
        except InvalidDpopProof:
            raise Unauthenticated("invalid_dpop_proof") from None
        except KonklavError:
            raise KonklavUnavailable() from None
        if accepted is None:
            raise Unauthenticated("invalid_token", presented.scheme)
        return accepted

    # r[impl item.py-fastapi.hooks]
    async def _verified(self, connection: HTTPConnection, token: AccessToken) -> None:
        for hook in self.on_verified:
            await hook(connection, token)

    async def _verify(self, connection: HTTPConnection) -> AccessToken | None:
        """For public routes, which make no decision: a presented token, verified."""
        presented = self._presented(connection)
        if presented is None:
            return None
        try:
            token = await self._client().verify_request_typed(
                authorization=presented.authorization,
                dpop=presented.dpop,
                method=_method(connection),
                url=self._url(connection),
            )
        except InvalidDpopProof:
            raise Unauthenticated("invalid_dpop_proof") from None
        except KonklavError:
            raise KonklavUnavailable() from None
        if token is None:
            raise Unauthenticated("invalid_token", presented.scheme)
        await self._verified(connection, token)
        return token


# -- injected tokens ----------------------------------------------------------

_Evaluated = Annotated[None, Depends(_evaluate)]


# r[impl item.py-fastapi.injected-tokens]
async def _optional_token(connection: HTTPConnection, _: _Evaluated) -> AccessToken | None:
    outcome: _Outcome = connection.scope[_SCOPE_KEY]
    if outcome.public:
        outcome = _Outcome(public=True, token=await KonklavRoutes.of(connection)._verify(connection))
        connection.scope[_SCOPE_KEY] = replace(outcome, public=False)
    return outcome.token


async def _current_token(token: Annotated[AccessToken | None, Depends(_optional_token)]) -> AccessToken:
    if token is None:
        raise Unauthenticated("missing_token")
    return token


def _of_kind(kind: str) -> Callable[..., Awaitable[AccessToken]]:
    async def token_of_kind(token: Annotated[AccessToken, Depends(_current_token)]) -> AccessToken:
        if token.knd != kind:
            raise Forbidden(DenyReason(code="token_kind"))
        return token

    token_of_kind.__name__ = f"_{kind}_token"
    return token_of_kind


_identity_token = _of_kind("identity")
_tenant_token = _of_kind("tenant")

CurrentToken = Annotated[AccessToken, Depends(_current_token)]
"""The request's verified token, of any kind the route's policy admits."""
OptionalToken = Annotated[AccessToken | None, Depends(_optional_token)]
"""The request's verified token, or `None` on a public route without one."""
IdentityToken = Annotated[AccessToken, Depends(_identity_token)]
"""The request's verified `identity` token."""
TenantToken = Annotated[AccessToken, Depends(_tenant_token)]
"""The request's verified `tenant` token."""

# r[impl item.py-fastapi.injected-kinds]
_INJECTED: dict[Callable[..., Any], tuple[str, frozenset[str]]] = {
    _optional_token: ("OptionalToken", TOKEN_KINDS),
    _current_token: ("CurrentToken", TOKEN_KINDS),
    _identity_token: ("IdentityToken", frozenset({"identity"})),
    _tenant_token: ("TenantToken", frozenset({"tenant"})),
}
