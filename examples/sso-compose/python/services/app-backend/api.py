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
from konklav_relying import KonklavError, RelyingClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from example import claims_of, secrets, split_key

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

notes: deque[dict[str, Any]] = deque(
    [{"text": "Welcome! Editors can add notes.", "author": "the example", "at": time.time() * 1000}],
    maxlen=50,
)


class Refused(Exception):
    def __init__(self, status: int, message: str, challenge: str | None = None) -> None:
        self.status, self.message, self.challenge = status, message, challenge


def presented(request: Request) -> dict[str, Any]:
    """The raw headers and the URL the browser addressed: the proof's
    `htu` names this public URL, not the container's."""
    authorization = request.headers.get("authorization")
    if not authorization:
        raise Refused(401, "sign in first", 'DPoP algs="ES256"')
    return {
        "authorization": authorization,
        "dpop": request.headers.get("dpop"),
        "method": request.method,
        "url": f"{PUBLIC_URL}{request.url.path}",
    }


async def decide(request: Request, action: str) -> dict[str, Any]:
    """Allows the request if its token holds `action`, or raises."""
    try:
        decision = await konklav.decide_request(
            **presented(request),
            requirements={"global": [action], "token_kinds": ["identity"]},
        )
    except KonklavError:
        # Konklav couldn't be reached and the caches can't be trusted: deny.
        raise Refused(503, "authorization is unavailable; try again") from None
    if decision["decision"] == "allow":
        return decision
    reason = decision.get("reason")
    if reason == "invalid_dpop_proof":
        raise Refused(401, "the DPoP proof is missing, invalid or replayed", 'DPoP error="invalid_dpop_proof"')
    if reason == "invalid_token":
        raise Refused(401, "the token is invalid or its session has ended", 'DPoP error="invalid_token"')
    raise Refused(403, f"your roles don't grant {action}")


async def can(request: Request) -> JSONResponse:
    """Whether the caller holds one of the app's actions. One per request,
    since a proof is accepted only once."""
    action = request.path_params["action"]
    if action not in ACTIONS:
        raise Refused(404, f"no action {action}")
    try:
        await decide(request, action)
    except Refused as refused:
        if refused.status != 403:
            raise
        return JSONResponse({"action": action, "allowed": False})
    return JSONResponse({"action": action, "allowed": True})


async def list_notes(request: Request) -> JSONResponse:
    await decide(request, "notes:read")
    return JSONResponse({"notes": list(reversed(notes))})


async def add_note(request: Request) -> JSONResponse:
    await decide(request, "notes:write")
    # The relying core verified the token above; read who it names.

    subject = claims_of(request.headers["authorization"].partition(" ")[2])["sub"]
    text = str((await request.json()).get("text", "")).strip()[:200]
    if not text:
        return JSONResponse({"message": "a note needs text"}, status_code=400)
    notes.append({"text": text, "author": subject[:8], "at": time.time() * 1000})
    return JSONResponse({"ok": True}, status_code=201)


def handle(endpoint):
    async def wrapped(request: Request) -> JSONResponse:
        try:
            return await endpoint(request)
        except Refused as refused:
            headers = {"www-authenticate": refused.challenge} if refused.challenge else None
            return JSONResponse({"message": refused.message}, status_code=refused.status, headers=headers)

    return wrapped


@contextlib.asynccontextmanager
async def lifespan(_: Starlette):
    await konklav.start()
    for _ in range(300):
        if konklav.is_trusted():
            break
        await asyncio.sleep(0.1)
    print("following Konklav's change feed", flush=True)
    yield
    await konklav.stop()


app = Starlette(
    routes=[
        Route("/api/can/{action}", handle(can)),
        Route("/api/notes", handle(list_notes), methods=["GET"]),
        Route("/api/notes", handle(add_note), methods=["POST"]),
    ],
    middleware=[
        Middleware(
            CORSMiddleware,
            allow_origins=[os.environ["FRONTEND_ORIGIN"]],
            allow_methods=["GET", "POST"],
            allow_headers=["authorization", "dpop", "content-type"],
            expose_headers=["www-authenticate"],
            # No cookies: the token and proof are the only credentials.
            allow_credentials=False,
        )
    ],
    lifespan=lifespan,
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3001)
