"""
Route policies decided by a real `RelyingClient` against a server on a fresh
database, started by the `test-server` binary from `examples/`.

Skipped unless `KONKLAV_TEST_SERVER` names that binary, as `mise run
py-fastapi:test` (part of `mise run test`) sets it.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, WebSocket
from fastapi.requests import HTTPConnection
from fastapi.testclient import TestClient
from konklav_control_plane import BearerToken, ControlPlaneClient
from konklav_relying import AccessToken, RelyingClient, StepUp
from starlette.websockets import WebSocketDisconnect

from konklav_fastapi import KonklavRoutes, RequestDecider, RoutePolicy, TenantToken
from support import DpopKey

PASSWORD = "correct horse battery"
URL = "http://testserver"


@dataclass
class World:
    server: dict[str, Any]
    key_id: str
    secret: str
    cursor: int
    email: str
    reader_tenant: str
    other_tenant: str


@pytest.fixture(scope="module")
def server() -> Iterator[dict[str, Any]]:
    binary = os.environ.get("KONKLAV_TEST_SERVER")
    if not binary:
        pytest.skip("set KONKLAV_TEST_SERVER, as `mise run py-fastapi:test` does")
    process = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout is not None
        line = process.stdout.readline()
        if not line:
            pytest.fail(f"{binary} didn't start a server (exit {process.wait(30)})")
        yield json.loads(line)
    finally:
        # Closing stdin stops the server and drops its database.
        assert process.stdin is not None
        process.stdin.close()
        process.wait(30)


@pytest.fixture(scope="module")
def world(server: dict[str, Any]) -> World:
    """
    A person who reads documents and manages user data in one tenant, where
    `user:write` is denied them, and is only a member of another.
    """

    async def setup() -> World:
        async with ControlPlaneClient(server["control"], auth=BearerToken(server["bootstrap_token"])) as control:
            reader, other, person, service = (str(uuid.uuid4()) for _ in range(4))
            email = f"{uuid.uuid4().hex}@example.com"
            async with control.batch() as batch:
                batch.catalog.put(
                    {
                        "actions": [
                            {"name": "document:read"},
                            {"name": "user:manage_data", "vouches": ["user:write"]},
                            {"name": "user:write"},
                        ]
                    }
                )
                batch.tenants.create(reader, {})
                batch.tenants.create(other, {})
                # Manages user data, which vouches for `user:write`, while
                # `user:write` itself is denied.
                batch.roles.put(
                    reader,
                    "reader",
                    {
                        "policies": [
                            {"action": "document:read", "effect": "allow"},
                            {"action": "user:manage_data", "effect": "allow"},
                            {"action": "user:write", "effect": "deny"},
                        ]
                    },
                )
                batch.subjects.create(person, {"kind": "human"})
                batch.credentials.create(person, {"kind": "password", "identifier": email, "password": PASSWORD})
                membership = str(uuid.uuid4())
                batch.memberships.create(membership, {"subject": person, "tenant": reader})
                batch.memberships.create(str(uuid.uuid4()), {"subject": person, "tenant": other})
                batch.subjects.create(service, {"kind": "service"})
                key = batch.credentials.create(service, {"kind": "secret_key"})
            written = await control.assignments.assign_to_membership(membership, {"role": "reader"})
            assert written.cursor is not None
            key_id, secret = key.result.value["secret_keys"]["a"].split(".", 1)
            return World(server, key_id, secret, written.cursor, email, reader, other)

    return asyncio.run(setup())


def tenant_token(world: World, tenant: str, key: DpopKey | None = None) -> str:
    """Signs in and selects `tenant`, bound to `key` when given."""
    issuer = world.server["issuer"]
    with httpx.Client(base_url=world.server["subject"]) as http:
        headers = {} if key is None else {"dpop": key.proof("POST", f"{issuer}/v1/login/password")}
        login = http.post("/v1/login/password", json={"identifier": world.email, "password": PASSWORD}, headers=headers)
        login.raise_for_status()
        identity = login.json()["access_token"]
        if key is None:
            headers = {"authorization": f"Bearer {identity}"}
        else:
            headers = {
                "authorization": f"DPoP {identity}",
                "dpop": key.proof("POST", f"{issuer}/v1/login/tenant", identity),
            }
        selected = http.post("/v1/login/tenant", json={"tenant": tenant}, headers=headers)
        selected.raise_for_status()
        return str(selected.json()["access_token"])


def app_for(world: World, verified: list[AccessToken]) -> FastAPI:
    routes = KonklavRoutes(
        route_tenant=route_tenant,
        on_verified=[lambda _, token: remember(verified, token)],
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        client = RelyingClient(
            relying_url=world.server["relying"],
            subject_url=world.server["subject"],
            key_id=world.key_id,
            secret=world.secret,
            issuer=world.server["issuer"],
            audience=world.server["audience"],
        )
        await client.start()
        await client.await_cursor(world.cursor)
        routes.client = client
        try:
            yield
        finally:
            await client.stop()

    app = FastAPI(lifespan=lifespan, dependencies=[RoutePolicy(tenant_actions={"document:read"})])

    @app.get("/tenants/{tenant}/documents")
    async def documents(tenant: str, token: TenantToken) -> dict[str, str | None]:
        return {"tenant": tenant, "tid": token.tid}

    @app.get("/sensitive", dependencies=[RoutePolicy(step_up=StepUp(min_methods=2))])
    async def sensitive() -> str:
        return "sensitive"

    @app.get("/users/data", dependencies=[RoutePolicy(tenant_actions={"user:manage_data"})])
    async def manage(decider: RequestDecider) -> bool:
        return (await decider.decide_typed({"tenant": ["user:write"]})).allowed

    @app.get("/users/plain")
    async def plain(decider: RequestDecider) -> bool:
        return (await decider.decide_typed({"tenant": ["user:write"]})).allowed

    @app.get("/users", dependencies=[RoutePolicy(tenant_actions={"user:write"})])
    async def write() -> str:
        return "written"

    @app.websocket("/live")
    async def live(socket: WebSocket, token: TenantToken) -> None:
        await socket.accept()
        await socket.send_json({"tid": token.tid})
        await socket.close()

    routes.install(app)
    return app


async def route_tenant(connection: HTTPConnection, _: AccessToken) -> str | None:
    return connection.path_params.get("tenant")


async def remember(verified: list[AccessToken], token: AccessToken) -> None:
    verified.append(token)


# r[verify item.py-fastapi.single-decision]
# r[verify item.py-fastapi.token-tenant]
# r[verify item.py-fastapi.outcomes]
# r[verify item.py-fastapi.hooks]
def test_bearer_tokens_are_decided_by_konklav(world: World) -> None:
    verified: list[AccessToken] = []
    reader = tenant_token(world, world.reader_tenant)
    member = tenant_token(world, world.other_tenant)
    with TestClient(app_for(world, verified), base_url=URL) as http:
        bearer = {"authorization": f"Bearer {reader}"}
        response = http.get(f"/tenants/{world.reader_tenant}/documents", headers=bearer)
        assert response.status_code == 200, response.text
        assert response.json() == {"tenant": world.reader_tenant, "tid": world.reader_tenant}

        response = http.get(f"/tenants/{world.other_tenant}/documents", headers=bearer)
        assert response.json() == {"error": {"code": "forbidden", "reason": "token_tenant"}}

        response = http.get(f"/tenants/{world.other_tenant}/documents", headers={"authorization": f"Bearer {member}"})
        assert response.status_code == 403
        assert response.json()["error"]["reason"] == {"missing_actions": {"actions": ["document:read"]}}

        response = http.get("/sensitive", headers=bearer)
        assert response.status_code == 401
        assert response.json() == {"error": {"code": "step_up", "requirement": {"min_methods": 2}}}
        assert response.headers["www-authenticate"] == 'Bearer error="insufficient_user_authentication"'

        assert http.get(f"/tenants/{world.reader_tenant}/documents").status_code == 401
        forged = reader[:-4] + ("AAAA" if not reader.endswith("AAAA") else "BBBB")
        response = http.get(f"/tenants/{world.reader_tenant}/documents", headers={"authorization": f"Bearer {forged}"})
        assert response.json() == {"error": {"code": "invalid_token"}}
        # Verified before the route tenant is compared: a forged token is
        # unauthenticated, wherever it points.
        response = http.get(f"/tenants/{world.other_tenant}/documents", headers={"authorization": f"Bearer {forged}"})
        assert response.json() == {"error": {"code": "invalid_token"}}
    # Every verified token reaches the hooks, allowed or not; forged ones don't.
    assert [token.tid for token in verified] == [world.reader_tenant] * 2 + [world.other_tenant] + [world.reader_tenant]


# r[verify item.py-fastapi.single-decision]
# r[verify item.py-fastapi.verify-then-decide]
# r[verify relying.verify.accepted-presentation]
def test_dpop_tokens_are_decided_with_their_one_proof(world: World) -> None:
    key = DpopKey()
    bound = tenant_token(world, world.reader_tenant, key)
    path = f"/tenants/{world.reader_tenant}/documents"
    with TestClient(app_for(world, []), base_url=URL) as http:
        proof = key.proof("GET", f"{URL}{path}", bound)
        headers = {"authorization": f"DPoP {bound}", "dpop": proof}
        response = http.get(path, headers=headers)
        assert response.status_code == 200, response.text

        replayed = http.get(path, headers=headers)
        assert replayed.status_code == 401
        assert replayed.headers["www-authenticate"] == 'DPoP error="invalid_dpop_proof"'

        as_bearer = http.get(path, headers={"authorization": f"Bearer {bound}"})
        assert as_bearer.json() == {"error": {"code": "invalid_dpop_proof"}}


# r[verify item.py-fastapi.token-extraction]
def test_websockets_take_the_token_from_the_query(world: World) -> None:
    reader = tenant_token(world, world.reader_tenant)
    with TestClient(app_for(world, []), base_url=URL) as http:
        with http.websocket_connect(f"/live?token={reader}") as socket:
            assert socket.receive_json() == {"tid": world.reader_tenant}
        member = tenant_token(world, world.other_tenant)
        with pytest.raises(WebSocketDisconnect) as closed, http.websocket_connect(f"/live?token={member}") as socket:
            socket.receive_json()
        assert closed.value.code == 1008


# r[verify item.py-fastapi.request-decider]
# r[verify relying.verify.route-authority]
def test_a_route_decision_vouches_for_its_handlers_decisions(world: World) -> None:
    reader = tenant_token(world, world.reader_tenant)
    bearer = {"authorization": f"Bearer {reader}"}
    with TestClient(app_for(world, []), base_url=URL) as http:
        # The route requires `user:manage_data`, which vouches for the
        # handler's `user:write` check, despite the deny.
        response = http.get("/users/data", headers=bearer)
        assert response.status_code == 200, response.text
        assert response.json() is True
        # A route that doesn't require it vouches for nothing.
        assert http.get("/users/plain", headers=bearer).json() is False
        # And a route requiring `user:write` itself is still forbidden.
        response = http.get("/users", headers=bearer)
        assert response.status_code == 403
        assert response.json()["error"]["reason"] == {"missing_actions": {"actions": ["user:write"]}}
