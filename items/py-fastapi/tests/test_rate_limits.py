"""Rate limits on FastAPI routes, with in-memory `RateLimit`s."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import APIRouter, FastAPI, WebSocket
from fastapi.requests import Request
from fastapi.testclient import TestClient
from konklav_relying import RateLimit, RateLimited, RateLimitWindow
from starlette.websockets import WebSocketDisconnect

from konklav_fastapi import KonklavRoutes, RoutePolicy, RoutePolicyError, RouteRateLimit, TenantToken
from konklav_fastapi.errors import retry_after_seconds
from support import FakeClient, token


def serve(app: FastAPI) -> TestClient:
    routes = KonklavRoutes()
    routes.client = FakeClient()
    routes.install(app)
    return TestClient(app)


def per_minute(name: str, size: int) -> RateLimit:
    return RateLimit(name, [RateLimitWindow(size=size, period=timedelta(minutes=1))])


def client_address(request: Request) -> str:
    return request.client.host if request.client else ""


# r[verify item.py-fastapi.rate-limit]
# r[verify item.py-fastapi.rate-limited]
def test_a_route_limit_answers_429_with_retry_after() -> None:
    app = FastAPI()
    limit = per_minute("route", 2)

    @app.get("/ping", dependencies=[RoutePolicy.public(), RouteRateLimit(limit, client_address)])
    async def ping() -> dict[str, str]:
        return {"ok": "yes"}

    with serve(app) as http:
        assert [http.get("/ping").status_code for _ in range(2)] == [200, 200]
        refused = http.get("/ping")
        assert refused.status_code == 429
        assert refused.json() == {"error": {"code": "rate_limited"}}
        # 30 s to wait, plus up to 3 s of jitter.
        assert 30 <= int(refused.headers["retry-after"]) <= 33


# r[verify item.py-fastapi.rate-limit]
def test_router_limits_apply_to_every_route_and_keys_can_use_the_token() -> None:
    app = FastAPI()
    limit = per_minute("router", 1)

    def subject(token: TenantToken) -> str:
        return token.sub

    router = APIRouter(dependencies=[RoutePolicy(tenant_actions={"read"}), RouteRateLimit(limit, subject)])

    @router.get("/a")
    async def a() -> None: ...

    @router.get("/b")
    async def b() -> None: ...

    app.include_router(router)
    with serve(app) as http:
        assert http.get("/a", headers={"authorization": f"Bearer {token(sub='s-1')}"}).status_code == 200
        assert http.get("/b", headers={"authorization": f"Bearer {token(sub='s-1')}"}).status_code == 429
        assert http.get("/b", headers={"authorization": f"Bearer {token(sub='s-2')}"}).status_code == 200
        # The token is verified before the key is read.
        assert http.get("/a").status_code == 401


# r[verify item.py-fastapi.rate-limited]
def test_limits_added_in_handlers_are_answered_too() -> None:
    app = FastAPI()
    limit = per_minute("handler", 1)

    @app.post("/login/{email}", dependencies=[RoutePolicy.public()])
    async def log_in(email: str) -> dict[str, str]:
        await limit.add(email)
        return {"email": email}

    with serve(app) as http:
        assert http.post("/login/a@example.com").status_code == 200
        assert http.post("/login/a@example.com").status_code == 429
        assert http.post("/login/b@example.com").status_code == 200


# r[verify item.py-fastapi.rate-limited]
def test_rate_limited_websockets_are_closed_with_try_again_later() -> None:
    app = FastAPI()
    limit = per_minute("socket", 1)

    @app.websocket("/live", dependencies=[RoutePolicy.public(), RouteRateLimit(limit, lambda: "everyone")])
    async def live(socket: WebSocket) -> None:
        await socket.accept()
        await socket.send_text("hi")
        await socket.close()

    with serve(app) as http:
        with http.websocket_connect("/live") as socket:
            assert socket.receive_text() == "hi"
        with pytest.raises(WebSocketDisconnect) as closed, http.websocket_connect("/live") as socket:
            socket.receive_text()
        assert closed.value.code == 1013


def test_keys_must_be_text_or_bytes() -> None:
    app = FastAPI()

    @app.get("/n", dependencies=[RoutePolicy.public(), RouteRateLimit(per_minute("typed", 1), lambda: 7)])
    async def n() -> None: ...

    with serve(app) as http, pytest.raises(TypeError, match="str or bytes"):
        http.get("/n")


def test_retry_after_rounds_up_and_adds_jitter() -> None:
    assert {retry_after_seconds(RateLimited(timedelta(milliseconds=1))) for _ in range(50)} <= {1, 2}
    values = {retry_after_seconds(RateLimited(timedelta(seconds=99.2))) for _ in range(200)}
    assert min(values) >= 100
    assert max(values) <= 110
    assert len(values) > 1


# -- key templates ------------------------------------------------------------


def bearer(**claims: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token(**claims)}"}


# r[verify item.py-fastapi.rate-limit-template]
def test_templates_key_on_path_parameters_and_token_claims() -> None:
    app = FastAPI()
    limit = per_minute("template", 1)

    @app.get(
        "/projects/{project}",
        dependencies=[RoutePolicy(tenant_actions={"read"}), RouteRateLimit(limit, "{token:sub}/{path:project}")],
    )
    async def read(project: str) -> None: ...

    fake = FakeClient()
    routes = KonklavRoutes()
    routes.client = fake
    routes.install(app)
    with TestClient(app) as http:
        assert http.get("/projects/p-1", headers=bearer(sub="s-1")).status_code == 200
        assert http.get("/projects/p-1", headers=bearer(sub="s-1")).status_code == 429
        assert http.get("/projects/p-2", headers=bearer(sub="s-1")).status_code == 200
        assert http.get("/projects/p-1", headers=bearer(sub="s-2")).status_code == 200
    # One verification and one decision per request: the template reads the
    # token the policy verified.
    assert len(fake.decided) == 4


# r[verify item.py-fastapi.rate-limit-template]
def test_template_parts_cant_run_together() -> None:
    app = FastAPI()
    limit = per_minute("joined", 1)

    @app.get("/{a}/{b}", dependencies=[RoutePolicy.public(), RouteRateLimit(limit, "{path:a}{path:b}")])
    async def joined(a: str, b: str) -> None: ...

    with serve(app) as http:
        assert http.get("/x/yz").status_code == 200
        assert http.get("/xy/z").status_code == 200, "a different key, though the values join the same"
        assert http.get("/x/yz").status_code == 429


# r[verify item.py-fastapi.rate-limit-template]
@pytest.mark.parametrize(
    ("template", "why"),
    [
        ("{path:a", "expected"),
        ("{path:}", "expected"),
        ("{query:a}", "path, token or client"),
        ("{token:jti}", "knd, sid, sub, tid"),
        ("{token:tid", "expected"),
        ("{client:host}", "client:address"),
        ("a}b", "unmatched"),
    ],
)
def test_malformed_templates_are_refused(template: str, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        RouteRateLimit(per_minute("bad", 1), template)


def test_literal_braces_and_constant_templates() -> None:
    app = FastAPI()
    limit = per_minute("constant", 1)

    @app.get("/a", dependencies=[RoutePolicy.public(), RouteRateLimit(limit, "{{everyone}}")])
    async def a() -> None: ...

    @app.get("/b", dependencies=[RoutePolicy.public(), RouteRateLimit(limit, "{{everyone}}")])
    async def b() -> None: ...

    with serve(app) as http:
        assert http.get("/a").status_code == 200
        assert http.get("/b").status_code == 429, "one key for both"


# r[verify item.py-fastapi.rate-limit-template-validation]
@pytest.mark.parametrize(
    ("policy", "template", "why"),
    [
        (RoutePolicy(tenant_actions={"read"}), "{path:project}", "no `project` path parameter"),
        (RoutePolicy.public(), "{token:sub}", "policy is public"),
        (RoutePolicy(token_kinds={"identity", "tenant"}), "{token:tid}", "only tenant tokens carry"),
    ],
)
def test_startup_refuses_templates_the_route_cant_render(policy: RoutePolicy, template: str, why: str) -> None:
    app = FastAPI()
    router = APIRouter(dependencies=[RouteRateLimit(per_minute("checked", 1), template)])

    @router.get("/items/{item}", dependencies=[policy])
    async def item(item: str) -> None: ...

    app.include_router(router)
    with pytest.raises(RoutePolicyError, match=why), serve(app):
        pass


def test_startup_accepts_templates_the_route_can_render() -> None:
    app = FastAPI()
    limit = per_minute("fine", 5)

    @app.get(
        "/items/{item}",
        dependencies=[
            RoutePolicy(tenant_actions={"read"}),
            RouteRateLimit(limit, "{token:tid}/{token:sub}/{token:sid}/{token:knd}/{path:item}/{client:address}"),
        ],
    )
    async def item(item: str) -> None: ...

    with serve(app) as http:
        assert http.get("/items/i-1", headers=bearer()).status_code == 200


# -- client addresses -----------------------------------------------------------


def address_app(trusted_proxies: list[str] | None = None) -> tuple[FastAPI, KonklavRoutes]:
    app = FastAPI()
    routes = KonklavRoutes(trusted_proxies=trusted_proxies or [])
    routes.client = FakeClient()

    @app.get("/whoami", dependencies=[RoutePolicy.public()])
    async def whoami(request: Request) -> dict[str, str | None]:
        return {"address": routes.client_address(request)}

    routes.install(app)
    return app, routes


def whoami(app: FastAPI, peer: str, forwarded: list[str] | None = None) -> str | None:
    with TestClient(app, client=(peer, 50000)) as http:
        headers = [("x-forwarded-for", value) for value in forwarded or []]
        address: str | None = http.get("/whoami", headers=headers).json()["address"]
        return address


# r[verify item.py-fastapi.client-address]
def test_the_peer_is_the_client_unless_it_is_a_trusted_proxy() -> None:
    app, _ = address_app(trusted_proxies=["10.0.0.0/8", "::1"])
    assert whoami(app, "203.0.113.7", ["198.51.100.1"]) == "203.0.113.7", "an untrusted peer's header is ignored"
    assert whoami(app, "10.1.2.3", ["198.51.100.1"]) == "198.51.100.1"
    # The client's own claim comes first; proxies append.
    assert whoami(app, "10.1.2.3", ["192.0.2.66, 198.51.100.1, 10.9.9.9"]) == "198.51.100.1"
    assert whoami(app, "10.1.2.3", ["192.0.2.66", "198.51.100.1"]) == "198.51.100.1", "several headers"
    assert whoami(app, "10.1.2.3", ["10.0.0.1, 10.0.0.2"]) == "10.0.0.1", "only proxies: the first"
    assert whoami(app, "10.1.2.3", ["junk"]) == "10.1.2.3", "nothing usable: the peer"
    assert whoami(app, "::ffff:10.1.2.3", ["198.51.100.1"]) == "198.51.100.1", "IPv4-mapped peers"
    assert whoami(app, "::1", ["2001:db8::1"]) == "2001:db8::1"


# r[verify item.py-fastapi.client-address]
def test_without_trusted_proxies_the_peer_is_the_client() -> None:
    app, _ = address_app()
    assert whoami(app, "10.1.2.3", ["198.51.100.1"]) == "10.1.2.3"


def test_invalid_trusted_proxies_are_refused() -> None:
    with pytest.raises(ValueError):
        KonklavRoutes(trusted_proxies=["not-an-address"])


# r[verify item.py-fastapi.client-address]
def test_client_address_templates_limit_per_client() -> None:
    app = FastAPI()
    limit = per_minute("address", 1)

    @app.get("/ping", dependencies=[RoutePolicy.public(), RouteRateLimit(limit, "{client:address}")])
    async def ping() -> None: ...

    routes = KonklavRoutes(trusted_proxies=["10.0.0.1"])
    routes.client = FakeClient()
    routes.install(app)
    with TestClient(app, client=("10.0.0.1", 1)) as http:
        assert http.get("/ping", headers={"x-forwarded-for": "198.51.100.1"}).status_code == 200
        assert http.get("/ping", headers={"x-forwarded-for": "198.51.100.1"}).status_code == 429
        assert http.get("/ping", headers={"x-forwarded-for": "198.51.100.2"}).status_code == 200
