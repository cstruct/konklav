"""The app's backend, on http://localhost:3001: a relying system.

Every request must carry `Authorization: DPoP <token>` and a fresh `DPoP`
proof signed by the key the token is bound to. `konklav-relying` checks
both, verifies the token offline against Konklav's keys, and decides the
request from entitlements it keeps fresh from Konklav's change feed, so a
role the admin page removes, or a session it ends, stops working here
within about a second.
"""

import asyncio
import contextlib
import os
import time
from collections import deque
from typing import Any

import uvicorn
from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import HTTPConnection
from fastapi.responses import JSONResponse
from konklav_fastapi import (
    Forbidden,
    IdentityToken,
    KonklavDenied,
    KonklavRoutes,
    KonklavUnavailable,
    RoutePolicy,
    Unauthenticated,
)
from konklav_relying import KonklavError, RelyingClient

from example import secrets, split_key

PUBLIC_URL = os.environ["PUBLIC_URL"]
ACTIONS = ["notes:read", "notes:write"]

key_id, secret = split_key(secrets()["app_api_key"])
konklav = RelyingClient(
    relying_url=os.environ["KONKLAV_RELYING_URL"],
    subject_url=os.environ["KONKLAV_SUBJECT_URL"],
    key_id=key_id,
    secret=secret,
    issuer=os.environ["ISSUER"],
    # The `app` OIDC client's tokens carry this audience.
    audience="app-api",
)


def public_url(connection: HTTPConnection) -> str:
    """The URL the browser addressed: the proof's `htu` names this public
    URL, not the container's."""
    return f"{PUBLIC_URL}{connection.url.path}"


routes = KonklavRoutes(client=konklav, public_url=public_url)

notes: deque[dict[str, Any]] = deque(
    [{"text": "Welcome! Editors can add notes.", "author": "the example", "at": time.time() * 1000}],
    maxlen=50,
)

# The app's sign-in gives identity tokens: it selects no tenant.
notes_api = APIRouter(dependencies=[RoutePolicy(token_kinds={"identity"})])


@notes_api.get("/api/notes", dependencies=[RoutePolicy(global_actions={"notes:read"})])
async def list_notes() -> dict[str, Any]:
    return {"notes": list(reversed(notes))}


@notes_api.post("/api/notes", status_code=201, dependencies=[RoutePolicy(global_actions={"notes:write"})])
async def add_note(request: Request, token: IdentityToken) -> Any:
    # `token` is the token the relying core verified for this request.
    text = str((await request.json()).get("text", "")).strip()[:200]
    if not text:
        return JSONResponse({"message": "a note needs text"}, status_code=400)
    notes.append({"text": text, "author": token.sub[:8], "at": time.time() * 1000})
    return {"ok": True}


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    await konklav.start()
    for _ in range(300):
        if konklav.is_trusted():
            break
        await asyncio.sleep(0.1)
    print("following Konklav's change feed", flush=True)
    yield
    await konklav.stop()


app = FastAPI(lifespan=lifespan)


@app.get("/api/can/{action}", dependencies=[RoutePolicy.public()])
async def can(action: str, request: Request) -> Any:
    """Whether the caller holds one of the app's actions. The action comes
    from the path, so no route policy can name it: the route is public and
    decides itself. One per request, since a proof is accepted only once."""
    if action not in ACTIONS:
        return JSONResponse({"message": f"no action {action}"}, status_code=404)
    authorization = request.headers.get("authorization")
    if not authorization:
        raise Unauthenticated("missing_token")
    try:
        decision = await konklav.decide_request_typed(
            authorization=authorization,
            dpop=request.headers.get("dpop"),
            method=request.method,
            url=public_url(request),
            requirements={"global": [action], "token_kinds": ["identity"]},
        )
    except KonklavError:
        raise KonklavUnavailable() from None
    if decision.reason is not None and decision.reason.code in ("invalid_token", "invalid_dpop_proof"):
        raise Unauthenticated(decision.reason.code)
    return {"action": action, "allowed": decision.decision == "allow"}


MESSAGES = {
    "missing_token": "sign in first",
    "invalid_token": "the token is invalid or its session has ended",
    "invalid_dpop_proof": "the DPoP proof is missing, invalid or replayed",
    "konklav_unavailable": "authorization is unavailable; try again",
}


async def denied(_: Request, error: Exception) -> JSONResponse:
    """Answers refusals as the app's page reads errors: with a `message`."""
    assert isinstance(error, KonklavDenied)
    if isinstance(error, Forbidden) and error.reason.actions:
        message = f"your roles don't grant {', '.join(sorted(error.reason.actions))}"
    else:
        message = MESSAGES.get(error.code, error.code)
    return JSONResponse({"message": message}, status_code=error.status_code, headers=error.headers)


app.include_router(notes_api)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ["FRONTEND_ORIGIN"]],
    allow_methods=["GET", "POST"],
    allow_headers=["authorization", "dpop", "content-type"],
    expose_headers=["www-authenticate"],
    # No cookies: the token and proof are the only credentials.
    allow_credentials=False,
)
# Checks every route's policy at startup, and decides each request.
routes.install(app)
# After `install`, so it replaces the package's handler.
app.add_exception_handler(KonklavDenied, denied)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3001)
