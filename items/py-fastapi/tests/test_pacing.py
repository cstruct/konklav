"""
Route pacing and the pacing middleware. Requests go straight to the ASGI
app, timing when the response starts. Timing tests assert lower bounds, and
upper bounds only far from the floor, so a loaded machine can't fail them.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI, HTTPException, WebSocket
from fastapi.testclient import TestClient
from konklav_relying import Pacing
from pydantic import BaseModel

from konklav_fastapi import KonklavRoutes, PacingMiddleware, RoutePacing, RoutePolicy, RoutePolicyError
from support import FakeClient, token

PACING = Pacing(floor=timedelta(milliseconds=150))
# Below the floor, for scheduling slack.
AT_LEAST = 0.14
LONG = Pacing(floor=timedelta(seconds=30))
# Far below LONG's floor: whatever runs this quickly wasn't paced by it.
UNPACED = 10.0

pytestmark = pytest.mark.anyio


class Body(BaseModel):
    address: str


def installed(app: FastAPI) -> FastAPI:
    routes = KonklavRoutes()
    routes.client = FakeClient()
    routes.install(app)
    return app


async def request(
    app: Any, method: str, path: str, *, body: bytes = b"", headers: dict[str, str] | None = None, query: str = ""
) -> tuple[int, float]:
    """The status and the seconds until the response started."""
    raw_headers = [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    if body:
        raw_headers.append((b"content-type", b"application/json"))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "server": ("testserver", 80),
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": query.encode(),
        "headers": [(b"host", b"testserver"), *raw_headers],
    }
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    started: list[tuple[int, float]] = []
    start = time.monotonic()

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            started.append((message["status"], time.monotonic() - start))

    try:
        await app(scope, receive, send)
    except Exception:
        # Starlette's error middleware re-raises after answering with a 500.
        pass
    (answered,) = started
    return answered


def bearer() -> dict[str, str]:
    return {"authorization": f"Bearer {token()}"}


@pytest.fixture
def app() -> Iterator[FastAPI]:
    app = FastAPI()
    paced = APIRouter(dependencies=[RoutePacing(PACING), RoutePolicy(tenant_actions={"member:invite"})])

    @paced.post("/invites")
    async def invite(body: Body, limit: int = 1) -> dict[str, str]:
        return {"address": body.address}

    @paced.post("/conflicts")
    async def conflict() -> None:
        raise HTTPException(status_code=409)

    app.include_router(paced)

    @app.get("/plain", dependencies=[RoutePolicy.public()])
    async def plain() -> None:
        return None

    yield installed(app)


# r[verify item.py-fastapi.route-pacing]
async def test_route_pacing_paces_allows_denials_and_errors(app: FastAPI) -> None:
    invite = json.dumps({"address": "someone@example.com"}).encode()
    for headers, path, body, query, status in [
        (bearer(), "/invites", invite, "", 200),
        # A denial (KonklavDenied) from the RoutePolicy after it.
        ({}, "/invites", invite, "", 401),
        # The handler raises HTTPException.
        (bearer(), "/conflicts", b"", "", 409),
        # A parameter that doesn't validate: FastAPI resolves the
        # dependencies first, and answers with 422 after them.
        (bearer(), "/invites", invite, "limit=many", 422),
    ]:
        answered, taken = await request(app, "POST", path, body=body, headers=headers, query=query)
        assert answered == status
        assert taken >= AT_LEAST, (path, status, taken)


# r[verify item.py-fastapi.route-pacing]
async def test_route_pacing_waits_before_the_response_starts() -> None:
    app = FastAPI()

    @app.get("/slow-start", dependencies=[RoutePacing(PACING), RoutePolicy.public()])
    async def slow_start() -> dict[str, bool]:
        return {"ok": True}

    status, taken = await request(installed(app), "GET", "/slow-start")
    assert status == 200 and taken >= AT_LEAST


# r[verify item.py-fastapi.route-pacing]
async def test_route_pacing_on_the_app_and_include_router() -> None:
    app = FastAPI(dependencies=[RoutePacing(PACING)])
    router = APIRouter()

    @router.get("/a", dependencies=[RoutePolicy.public()])
    async def a() -> None:
        return None

    included = APIRouter()

    @included.get("/b", dependencies=[RoutePolicy.public()])
    async def b() -> None:
        return None

    app.include_router(router)
    second = FastAPI()
    second.include_router(included, dependencies=[RoutePacing(PACING)])
    for target, path in [(installed(app), "/a"), (installed(second), "/b")]:
        status, taken = await request(target, "GET", path)
        assert status == 200 and taken >= AT_LEAST


# r[verify item.py-fastapi.route-pacing.nested]
async def test_nested_route_pacings_wait_for_the_longest() -> None:
    longer = Pacing(floor=timedelta(milliseconds=300))
    app = FastAPI(dependencies=[RoutePacing(PACING)])

    @app.get("/nested", dependencies=[RoutePacing(longer), RoutePolicy.public()])
    async def nested() -> None:
        return None

    status, taken = await request(installed(app), "GET", "/nested")
    assert status == 200 and taken >= 0.29


# r[verify item.py-fastapi.route-pacing]
def test_route_pacing_leaves_websockets_alone() -> None:
    app = FastAPI(dependencies=[RoutePacing(LONG)])

    @app.websocket("/feed", dependencies=[RoutePolicy.public()])
    async def feed(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("hello")
        await websocket.close()

    start = time.monotonic()
    with TestClient(installed(app)) as client, client.websocket_connect("/feed") as websocket:
        assert websocket.receive_text() == "hello"
    assert time.monotonic() - start < UNPACED


# r[verify item.py-fastapi.route-pacing.order]
# r[verify item.py-fastapi.validation]
def test_startup_refuses_a_route_pacing_after_the_route_policy() -> None:
    app = FastAPI(dependencies=[RoutePolicy(tenant_actions={"member:invite"})])

    @app.post("/late", dependencies=[RoutePacing(PACING)])
    async def late() -> None:
        return None

    @app.post("/early", dependencies=[RoutePacing(PACING)])
    async def early() -> None:
        return None

    router = APIRouter(dependencies=[RoutePacing(PACING), RoutePolicy(tenant_actions={"a"})])

    @router.post("/fine")
    async def fine() -> None:
        return None

    other = FastAPI(dependencies=[RoutePacing(PACING)])
    other.include_router(router)
    KonklavRoutes().validate(other)

    with pytest.raises(RoutePolicyError) as raised:
        KonklavRoutes().validate(app)
    assert str(raised.value).splitlines()[1:] == [
        "POST /late: declares a RoutePacing after its RoutePolicy; declare it before, so denials are paced too",
        "POST /early: declares a RoutePacing after its RoutePolicy; declare it before, so denials are paced too",
    ]


def test_route_pacing_repr() -> None:
    assert repr(RoutePacing(PACING)) == f"RoutePacing({PACING!r})"
    assert RoutePacing(PACING).pacing == PACING


# r[verify item.py-fastapi.pacing-middleware]
async def test_the_middleware_paces_every_answer_for_its_paths() -> None:
    app = FastAPI()

    @app.post("/invites", dependencies=[RoutePolicy.public()])
    async def invite(body: Body) -> dict[str, str]:
        return {"address": body.address}

    @app.post("/failing", dependencies=[RoutePolicy.public()])
    async def failing() -> None:
        raise RuntimeError("unhandled")

    app.add_middleware(PacingMiddleware, pacing=PACING, paths={"/invites", "/failing", "/gone"})
    installed(app)
    for path, body, status in [
        ("/invites", json.dumps({"address": "a@example.com"}).encode(), 200),
        # Malformed JSON: FastAPI answers before any dependency runs.
        ("/invites", b"{", 422),
        ("/failing", b"", 500),
        ("/gone", b"", 404),
    ]:
        answered, taken = await request(app, "POST", path, body=body)
        assert answered == status
        assert taken >= AT_LEAST, (path, status, taken)


# r[verify item.py-fastapi.pacing-middleware]
async def test_the_middleware_leaves_other_paths_alone() -> None:
    app = FastAPI()

    @app.get("/plain", dependencies=[RoutePolicy.public()])
    async def plain() -> None:
        return None

    app.add_middleware(PacingMiddleware, pacing=LONG, paths={"/invites"})
    status, taken = await request(installed(app), "GET", "/plain")
    assert status == 200 and taken < UNPACED
    with pytest.raises(TypeError):
        PacingMiddleware(app, pacing=PACING, paths="/invites")
