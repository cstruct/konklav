"""Route policies on FastAPI apps, with a relying client that records what it is asked."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI, HTTPException, WebSocket
from fastapi.requests import HTTPConnection
from fastapi.testclient import TestClient
from konklav_relying import AccessToken, KonklavError, StepUp
from starlette.websockets import WebSocketDisconnect

from konklav_fastapi import (
    CurrentToken,
    IdentityToken,
    KonklavRoutes,
    OptionalToken,
    ResolvedScope,
    RoutePolicy,
    RoutePolicyError,
    TenantToken,
)
from support import FakeClient, token


def serve(app: FastAPI, routes: KonklavRoutes | None = None, client: FakeClient | None = None) -> TestClient:
    routes = routes or KonklavRoutes()
    routes.client = client or FakeClient()
    routes.install(app)
    return TestClient(app)


def bearer(raw: str | None = None) -> dict[str, str]:
    return {"authorization": f"Bearer {raw or token()}"}


def requirements(client: FakeClient) -> list[dict[str, Any]]:
    return [decided["requirements"] for decided in client.decided]


# r[verify item.py-fastapi.route-policy]
# r[verify item.py-fastapi.merge-order]
# r[verify item.py-fastapi.shared-dependency]
# r[verify item.py-fastapi.single-decision]
def test_policies_of_every_layer_merge_into_one_decision() -> None:
    app = FastAPI(dependencies=[RoutePolicy(token_kinds={"identity", "tenant"})])
    inner = APIRouter(dependencies=[RoutePolicy(tenant_actions={"router"}, step_up=StepUp(max_age_seconds=3600))])

    @inner.get("/documents/{project}", dependencies=[RoutePolicy(scope_actions={"project": {"document:read"}})])
    async def read(project: str, token: CurrentToken) -> dict[str, str]:
        return {"project": project, "sub": token.sub}

    outer = APIRouter(dependencies=[RoutePolicy(tenant_actions={"outer"})])
    outer.include_router(inner, dependencies=[RoutePolicy(tenant_actions={"include"}, token_kinds={"tenant"})])
    app.include_router(outer, prefix="/a", dependencies=[RoutePolicy(step_up=StepUp(max_age_seconds=60))])
    # The same router again, under other layers.
    app.include_router(inner, prefix="/b", dependencies=[RoutePolicy(tenant_actions={"b"})])

    fake = FakeClient()
    with serve(app, client=fake) as http:
        response = http.get("/a/documents/p-1", headers=bearer())
        assert response.status_code == 200, response.text
        assert response.json() == {"project": "p-1", "sub": "s-1"}
        assert http.get("/b/documents/p-2", headers=bearer()).status_code == 200

    assert requirements(fake) == [
        {
            "token_kinds": ["tenant"],
            "tenant": ["include", "outer", "router"],
            "scopes": [{"kind": "project", "id": "p-1", "actions": ["document:read"]}],
            "step_up": {"max_age_seconds": 60},
        },
        {
            "token_kinds": ["identity", "tenant"],
            "tenant": ["b", "router"],
            "scopes": [{"kind": "project", "id": "p-2", "actions": ["document:read"]}],
            "step_up": {"max_age_seconds": 3600},
        },
    ]
    assert fake.decided[0]["method"] == "GET"
    assert fake.decided[0]["url"] == "http://testserver/a/documents/p-1"
    assert fake.decided[0]["authorization"].startswith("Bearer ")


# r[verify item.py-fastapi.merge-order]
# r[verify item.py-fastapi.token-extraction]
def test_included_websocket_routes_merge_their_layers_and_take_the_token_from_the_query() -> None:
    router = APIRouter(dependencies=[RoutePolicy(tenant_actions={"router"})])

    @router.websocket("/live", dependencies=[RoutePolicy(tenant_actions={"route"})])
    async def live(socket: WebSocket, token: TenantToken) -> None:
        await socket.accept()
        await socket.send_json({"sub": token.sub})
        await socket.close()

    app = FastAPI()
    app.include_router(router, prefix="/ws", dependencies=[RoutePolicy(tenant_actions={"include"})])
    fake = FakeClient()
    with serve(app, client=fake) as http:
        with http.websocket_connect(f"/ws/live?token={token()}") as socket:
            assert socket.receive_json() == {"sub": "s-1"}
        with pytest.raises(WebSocketDisconnect) as closed, http.websocket_connect("/ws/live") as socket:
            socket.receive_json()
        assert closed.value.code == 1008
    assert requirements(fake) == [{"tenant": ["include", "route", "router"]}]
    assert fake.decided[0]["method"] == "GET"
    assert fake.decided[0]["url"].startswith("http://testserver/ws/live")


# r[verify item.py-fastapi.token-extraction]
def test_the_query_parameter_is_ignored_for_http_and_the_cookie_hook_is_read() -> None:
    app = FastAPI(dependencies=[RoutePolicy(tenant_actions={"a"})])

    @app.get("/")
    async def root() -> None:
        return None

    routes = KonklavRoutes(cookie=lambda connection: connection.cookies.get("session"))
    with serve(app, routes) as http:
        assert http.get(f"/?token={token()}").status_code == 401
        http.cookies.set("session", token())
        assert http.get("/").status_code == 200
        response = http.get("/", headers={"dpop": "proof"})
    assert routes.client.decided[-1]["authorization"].startswith("DPoP ")
    assert routes.client.decided[-1]["dpop"] == "proof"
    assert response.status_code == 200


# r[verify item.py-fastapi.admit-flags-operation]
def test_only_the_route_admits_flags() -> None:
    router = APIRouter(dependencies=[RoutePolicy(tenant_actions={"a"})])

    @router.get("/personal", dependencies=[RoutePolicy(admit_flags={"personal_only"})])
    async def personal() -> None:
        return None

    @router.get("/other")
    async def other() -> None:
        return None

    app = FastAPI()
    app.include_router(router)
    fake = FakeClient()
    with serve(app, client=fake) as http:
        http.get("/personal", headers=bearer())
        http.get("/other", headers=bearer())
    assert requirements(fake) == [{"tenant": ["a"], "admit_flags": ["personal_only"]}, {"tenant": ["a"]}]

    for declared in ("router", "include", "app"):
        router = APIRouter(dependencies=[RoutePolicy(admit_flags={"personal_only"})] if declared == "router" else [])

        @router.get("/x", dependencies=[RoutePolicy(tenant_actions={"a"}, admit_flags={"personal_only"})])
        async def x() -> None:
            return None

        app = FastAPI(dependencies=[RoutePolicy(admit_flags={"kiosk"})] if declared == "app" else [])
        app.include_router(router, dependencies=[RoutePolicy(admit_flags=set())] if declared == "include" else [])
        with pytest.raises(RoutePolicyError, match="only the route's own RoutePolicy can admit flags"):
            KonklavRoutes().validate(app)


# r[verify item.py-fastapi.public]
def test_public_routes_read_no_token() -> None:
    app = FastAPI()

    @app.get("/health", dependencies=[RoutePolicy.public()])
    async def health() -> str:
        return "ok"

    fake = FakeClient()
    with serve(app, client=fake) as http:
        assert http.get("/health", headers={"authorization": "Bearer garbage"}).json() == "ok"
    assert fake.decided == [] and fake.verified == []


# r[verify item.py-fastapi.injected-tokens]
# r[verify item.py-fastapi.hooks]
def test_optional_tokens_on_public_routes_are_verified() -> None:
    app = FastAPI()
    seen: list[str] = []

    @app.get("/hello", dependencies=[RoutePolicy.public()])
    async def hello(token: OptionalToken) -> str:
        return "anyone" if token is None else token.sub

    async def hook(connection: HTTPConnection, verified: AccessToken) -> None:
        seen.append(verified.sub)

    fake = FakeClient()
    with serve(app, KonklavRoutes(on_verified=[hook]), fake) as http:
        assert http.get("/hello").json() == "anyone"
        assert http.get("/hello", headers=bearer()).json() == "s-1"
        assert http.get("/hello", headers=bearer("invalid")).status_code == 401
        assert http.get("/hello", headers=bearer("unreachable")).status_code == 503
    assert len(fake.verified) == 3 and fake.decided == []
    assert seen == ["s-1"]


# r[verify item.py-fastapi.outcomes]
@pytest.mark.parametrize(
    ("outcome", "status", "body", "challenge"),
    [
        (
            {"decision": "deny", "reason": "invalid_token"},
            401,
            {"code": "invalid_token"},
            'Bearer error="invalid_token"',
        ),
        (
            {"decision": "deny", "reason": "invalid_dpop_proof"},
            401,
            {"code": "invalid_dpop_proof"},
            'DPoP error="invalid_dpop_proof"',
        ),
        (
            {"decision": "deny", "reason": {"missing_actions": {"actions": ["a"]}}},
            403,
            {"code": "forbidden", "reason": {"missing_actions": {"actions": ["a"]}}},
            None,
        ),
        ({"decision": "deny", "reason": "token_kind"}, 403, {"code": "forbidden", "reason": "token_kind"}, None),
        (
            {"decision": "step_up", "requirement": {"min_methods": 2}},
            401,
            {"code": "step_up", "requirement": {"min_methods": 2}},
            None,
        ),
        (KonklavError("down"), 503, {"code": "konklav_unavailable"}, None),
    ],
)
def test_decisions_map_to_answers(outcome: Any, status: int, body: dict[str, Any], challenge: str | None) -> None:
    app = FastAPI(dependencies=[RoutePolicy(tenant_actions={"a"})])

    @app.get("/")
    async def root() -> None:
        return None

    with serve(app, client=FakeClient(decide=lambda _: outcome)) as http:
        response = http.get("/", headers=bearer())
    assert response.status_code == status
    assert response.json() == {"error": body}
    assert response.headers.get("www-authenticate") == challenge


# r[verify item.py-fastapi.outcomes]
# r[verify item.py-fastapi.verify-then-decide]
def test_tokens_that_dont_verify_are_refused_before_anything_reads_them() -> None:
    app = FastAPI(dependencies=[RoutePolicy(tenant_actions={"a"})])

    @app.get("/")
    async def root() -> None:
        return None

    fake = FakeClient()
    asked: list[str] = []

    async def route_tenant(connection: HTTPConnection, verified: AccessToken) -> str | None:
        asked.append(verified.sub)
        return None

    with serve(app, KonklavRoutes(route_tenant=route_tenant), fake) as http:
        missing = http.get("/")
        assert missing.json() == {"error": {"code": "missing_token"}}
        assert missing.headers["www-authenticate"] == "Bearer, DPoP"
        invalid = http.get("/", headers=bearer("not-a-jwt"))
        assert invalid.json() == {"error": {"code": "invalid_token"}}
        assert invalid.headers["www-authenticate"] == 'Bearer error="invalid_token"'
        # Challenged in the scheme the token came in.
        invalid = http.get("/", headers={"authorization": "DPoP not-a-jwt", "dpop": "proof"})
        assert invalid.headers["www-authenticate"] == 'DPoP error="invalid_token"'
        response = http.get("/", headers={"authorization": "DPoP bad-proof", "dpop": "proof"})
        assert response.json() == {"error": {"code": "invalid_dpop_proof"}}
        assert response.headers["www-authenticate"] == 'DPoP error="invalid_dpop_proof"'
        assert http.get("/", headers=bearer("unreachable")).status_code == 503
    # Refused tokens reach no application code and no decision.
    assert fake.decided == [] and asked == []
    assert [request["method"] for request in fake.accepted] == ["GET"] * 4


# r[verify item.py-fastapi.outcomes]
def test_denials_can_be_handled_by_the_application() -> None:
    from fastapi.responses import PlainTextResponse

    from konklav_fastapi import Forbidden

    app = FastAPI(dependencies=[RoutePolicy(tenant_actions={"a"})])

    @app.get("/")
    async def root() -> None:
        return None

    routes = KonklavRoutes()
    routes.client = FakeClient(decide=lambda _: {"decision": "deny", "reason": "no_tenant"})
    routes.install(app)

    async def teapot(_: Any, error: Exception) -> PlainTextResponse:
        assert isinstance(error, Forbidden)
        return PlainTextResponse(error.reason.code, status_code=418)

    app.add_exception_handler(Forbidden, teapot)
    with TestClient(app) as http:
        response = http.get("/", headers=bearer())
    assert (response.status_code, response.text) == (418, "no_tenant")


# r[verify item.py-fastapi.token-tenant]
def test_a_route_tenant_other_than_the_tokens_is_denied_before_deciding() -> None:
    app = FastAPI(dependencies=[RoutePolicy(tenant_actions={"a"})])

    @app.get("/tenants/{tenant}/things")
    async def things(tenant: str) -> str:
        return tenant

    @app.get("/things")
    async def mine() -> str:
        return "mine"

    async def route_tenant(connection: HTTPConnection, _: AccessToken) -> str | None:
        return connection.path_params.get("tenant")

    fake = FakeClient()
    with serve(app, KonklavRoutes(route_tenant=route_tenant), fake) as http:
        assert http.get("/tenants/t-1/things", headers=bearer()).json() == "t-1"
        response = http.get("/tenants/t-2/things", headers=bearer())
        assert response.status_code == 403
        assert response.json() == {"error": {"code": "forbidden", "reason": "token_tenant"}}
        # An identity token targets no tenant.
        assert http.get("/tenants/t-1/things", headers=bearer(token(tenant=None))).status_code == 403
        assert http.get("/things", headers=bearer(token(tenant=None))).status_code == 200
    assert len(fake.decided) == 2


# r[verify item.py-fastapi.scope-resolvers]
def test_scope_resolvers_name_ids_kinds_and_owner_tenants() -> None:
    app = FastAPI()

    @app.get(
        "/projects/{project}/documents/{document}",
        dependencies=[RoutePolicy(scope_actions={"project": {"project:read"}, "document": {"document:read"}})],
    )
    async def read() -> None:
        return None

    async def document(connection: HTTPConnection, claims: AccessToken) -> ResolvedScope:
        # The document's own kind decides: a resource of several kinds.
        doc = connection.path_params["document"]
        kind = "personal_document" if doc.startswith("me-") else "project_document"
        return ResolvedScope(id=doc, kind=kind, tenant="t-owner" if claims.tid == "t-1" else None)

    fake = FakeClient()
    with serve(app, KonklavRoutes(scope_resolvers={"document": document}), fake) as http:
        http.get("/projects/p-1/documents/me-1", headers=bearer())
        http.get("/projects/p-1/documents/d-1", headers=bearer(token(tenant="t-2")))
    assert [r["scopes"] for r in requirements(fake)] == [
        [
            {"tenant": "t-owner", "kind": "personal_document", "id": "me-1", "actions": ["document:read"]},
            {"kind": "project", "id": "p-1", "actions": ["project:read"]},
        ],
        [
            {"kind": "project_document", "id": "d-1", "actions": ["document:read"]},
            {"kind": "project", "id": "p-1", "actions": ["project:read"]},
        ],
    ]


# r[verify item.py-fastapi.hooks]
# r[verify item.py-fastapi.verify-then-decide]
def test_hooks_run_in_order_on_verified_tokens_before_deciding_and_can_refuse() -> None:
    app = FastAPI(dependencies=[RoutePolicy(tenant_actions={"a"})])

    @app.get("/")
    async def root(token: CurrentToken) -> str:
        return token.sub

    seen: list[str] = []

    def hook(name: str, refuse: bool = False) -> Callable[[HTTPConnection, AccessToken], Any]:
        async def run(connection: HTTPConnection, verified: AccessToken) -> None:
            seen.append(f"{name}:{verified.sub}")
            if refuse and verified.sub == "banned":
                raise HTTPException(403, "banned")

        return run

    allow = True
    fake = FakeClient(decide=lambda _: {"decision": "allow"} if allow else {"decision": "deny", "reason": "no_tenant"})
    with serve(app, KonklavRoutes(on_verified=[hook("first"), hook("second", refuse=True)]), fake) as http:
        assert http.get("/", headers=bearer()).json() == "s-1"
        assert http.get("/", headers=bearer(token(sub="banned"))).status_code == 403
        allow = False
        assert http.get("/", headers=bearer()).status_code == 403
    # Hooks run on every verified token, before the decision; a refusal
    # means no decision at all.
    assert seen == ["first:s-1", "second:s-1", "first:banned", "second:banned", "first:s-1", "second:s-1"]
    assert len(fake.decided) == 2


# r[verify item.py-fastapi.injected-tokens]
def test_tokens_of_a_kind_are_injected() -> None:
    app = FastAPI()

    @app.get("/me", dependencies=[RoutePolicy(token_kinds={"identity"})])
    async def me(token: IdentityToken) -> str:
        return token.knd

    @app.get("/here", dependencies=[RoutePolicy(tenant_actions={"a"})])
    async def here(token: TenantToken, again: CurrentToken) -> str:
        assert token is again
        return f"{token.knd}:{token.tid}"

    fake = FakeClient()
    with serve(app, client=fake) as http:
        assert http.get("/me", headers=bearer(token(kind="identity", tenant=None))).json() == "identity"
        assert http.get("/here", headers=bearer()).json() == "tenant:t-1"
    assert len(fake.decided) == 2


# r[verify item.py-fastapi.validation]
# r[verify item.py-fastapi.injected-kinds]
def test_startup_validation_lists_every_bad_route() -> None:
    app = FastAPI()

    @app.get("/none")
    async def none() -> None:
        return None

    @app.get("/public-and-more", dependencies=[RoutePolicy.public(), RoutePolicy(tenant_actions={"a"})])
    async def public_and_more() -> None:
        return None

    @app.get("/scopes", dependencies=[RoutePolicy(scope_actions={"project": {"a"}})])
    async def scopes() -> None:
        return None

    @app.get(
        "/kinds", dependencies=[RoutePolicy(token_kinds={"identity"}), RoutePolicy(token_kinds={"tenant"})]
    )
    async def kinds() -> None:
        return None

    @app.get("/methods", dependencies=[RoutePolicy(step_up=StepUp(allowed_methods={"pwd"})),
                                        RoutePolicy(step_up=StepUp(allowed_methods={"otp"}))])
    async def methods() -> None:
        return None

    @app.get("/facts", dependencies=[RoutePolicy(tenant_facts={"t": ["a"]}), RoutePolicy(tenant_facts={"t": ["b"]})])
    async def facts() -> None:
        return None

    @app.get("/identity", dependencies=[RoutePolicy(tenant_actions={"a"})])
    async def identity(token: IdentityToken) -> None:
        return None

    @app.get("/anyone", dependencies=[RoutePolicy.public()])
    async def anyone(token: CurrentToken) -> None:
        return None

    @app.websocket("/socket")
    async def socket(websocket: WebSocket) -> None:
        return None

    @app.get("/fine", dependencies=[RoutePolicy(token_kinds={"identity", "tenant"})])
    async def fine(token: CurrentToken, project: str) -> None:
        return None

    with pytest.raises(RoutePolicyError) as raised:
        KonklavRoutes().validate(app)
    assert str(raised.value).splitlines() == [
        "Routes without a valid route policy:",
        "GET /none: declares no RoutePolicy; declare one, or RoutePolicy.public()",
        "GET /public-and-more: a public policy can't be merged with constraints; override it instead",
        "GET /scopes: needs a `project` scope: configure a scope resolver or add a `project` path parameter",
        "GET /kinds: merged policies admit no token kind",
        "GET /methods: merged policies allow no step-up method",
        "GET /facts: the merged policies allow no value of the tenant fact `t`",
        "GET /identity: injects IdentityToken, which takes identity tokens, but its policy admits tenant",
        "GET /anyone: injects CurrentToken, but its policy is public; use OptionalToken",
        "WEBSOCKET /socket: declares no RoutePolicy; declare one, or RoutePolicy.public()",
    ]

    async def resolver(connection: HTTPConnection, claims: AccessToken) -> str:
        return "p"

    # Startup runs the same validation.
    routes = KonklavRoutes(scope_resolvers={"project": resolver})
    routes.install(app)
    with pytest.raises(RoutePolicyError, match="GET /none"), TestClient(app):
        pass


# r[verify item.py-fastapi.openapi]
def test_openapi_publishes_each_operations_policy() -> None:
    router = APIRouter(dependencies=[RoutePolicy(tenant_actions={"project:read"})])

    @router.post(
        "/projects/{project}",
        dependencies=[RoutePolicy(scope_actions={"project": {"project:write"}}, admit_flags={"personal_only"})],
    )
    async def write(project: str) -> None:
        return None

    app = FastAPI()
    app.include_router(router, prefix="/v1")

    @app.get("/health", dependencies=[RoutePolicy.public()])
    async def health() -> None:
        return None

    with serve(app) as http:
        paths = http.get("/openapi.json").json()["paths"]
    assert paths["/v1/projects/{project}"]["post"]["x-konklav-policy"] == {
        "public": False,
        "tenant": ["project:read"],
        "scopes": [{"kind": "project", "actions": ["project:write"]}],
        "admit_flags": ["personal_only"],
    }
    assert paths["/health"]["get"]["x-konklav-policy"] == {"public": True}
