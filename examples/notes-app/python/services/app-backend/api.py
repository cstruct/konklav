"""The app's backend, on http://localhost:3001: a relying system.

Every request must carry `Authorization: DPoP <token>` and a fresh `DPoP`
proof signed by the key the token is bound to. `konklav-relying` checks
both, verifies the token offline against Konklav's keys, and decides the
request from entitlements it keeps fresh from Konklav's change feed, so a
role the admin page removes, or a session it ends, stops working here
within about a second.

Compose runs two replicas behind a load balancer. Adding notes is rate
limited per person, through Valkey so the replicas count together, and in
each replica's memory while Valkey is unavailable.
"""

import asyncio
import contextlib
import os
import socket
from datetime import timedelta
from typing import Any

import asyncpg
import redis.asyncio
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
    RouteRateLimit,
    Unauthenticated,
)
from konklav_relying import KonklavError, RateLimit, RateLimitWindow, RelyingClient

from example import secrets, split_key

PUBLIC_URL = os.environ["PUBLIC_URL"]
ACTIONS = ["notes:read", "notes:write"]
# Which replica answered, so the page can show the load balancer at work.
REPLICA = socket.gethostname()

SECRETS = secrets()
key_id, secret = split_key(SECRETS["app_api_key"])
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

# Five notes at once, then one every 12 seconds, per person. Every replica
# shares the count through Valkey; while Valkey is unavailable each replica
# counts alone and allows its share: 2 of the 5 (`local_divisor`).
note_writes = RateLimit(
    "notes-app.note-writes",
    [RateLimitWindow(size=5, period=timedelta(minutes=1))],
    # Valkey, through the redis client library: it speaks the same protocol.
    redis=redis.asyncio.Redis.from_url(os.environ["REDIS_URL"]),
    # Keys are hashed under this before they reach Valkey. The setup service
    # generated it, so every replica has the same one.
    secret=SECRETS["rate_limit_secret"].encode(),
    local_divisor=int(os.environ["REPLICAS"]),
)

# The notes, in Postgres, so that both replicas serve the same ones.
database: asyncpg.Pool | None = None


async def open_database() -> asyncpg.Pool:
    pool = await asyncpg.create_pool(os.environ["NOTES_DATABASE_URL"], min_size=1, max_size=5)
    async with pool.acquire() as connection, connection.transaction():
        # Both replicas start together; the lock makes one create the table.
        await connection.execute("SELECT pg_advisory_xact_lock(1)")
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                text text NOT NULL,
                author text NOT NULL,
                at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        if await connection.fetchval("SELECT count(*) FROM notes") == 0:
            await connection.execute(
                "INSERT INTO notes (text, author) VALUES ($1, $2)", "Welcome! Editors can add notes.", "the example"
            )
    return pool


def notes_db() -> asyncpg.Pool:
    assert database is not None
    return database


# The app's sign-in gives identity tokens: it selects no tenant.
notes_api = APIRouter(dependencies=[RoutePolicy(token_kinds={"identity"})])


@notes_api.get("/api/notes", dependencies=[RoutePolicy(global_actions={"notes:read"})])
async def list_notes() -> dict[str, Any]:
    rows = await notes_db().fetch("SELECT text, author, at FROM notes ORDER BY id DESC LIMIT 50")
    notes = [{"text": row["text"], "author": row["author"], "at": row["at"].timestamp() * 1000} for row in rows]
    return {"notes": notes, "replica": REPLICA}


@notes_api.post(
    "/api/notes",
    status_code=201,
    dependencies=[
        RoutePolicy(global_actions={"notes:write"}),
        # After the policy, so it counts only allowed requests, keyed by the
        # verified token's subject. A refusal is 429 with `Retry-After`.
        RouteRateLimit(note_writes, "{token:sub}"),
    ],
)
async def add_note(request: Request, token: IdentityToken) -> Any:
    # `token` is the token the relying core verified for this request.
    text = str((await request.json()).get("text", "")).strip()[:200]
    if not text:
        return JSONResponse({"message": "a note needs text"}, status_code=400)
    await notes_db().execute("INSERT INTO notes (text, author) VALUES ($1, $2)", text, token.sub[:8])
    return {"ok": True, "replica": REPLICA}


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    global database
    database = await open_database()
    await konklav.start()
    for _ in range(300):
        if konklav.is_trusted():
            break
        await asyncio.sleep(0.1)
    print("following Konklav's change feed", flush=True)
    yield
    await konklav.stop()
    await database.close()


app = FastAPI(lifespan=lifespan)


@app.get("/healthz", dependencies=[RoutePolicy.public()])
async def healthz() -> dict[str, str]:
    """For compose's healthcheck: answers once the app has started."""
    return {"replica": REPLICA}


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
        scheme = "DPoP" if authorization.partition(" ")[0].lower() == "dpop" else "Bearer"
        raise Unauthenticated(decision.reason.code, scheme)
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
    # `Retry-After` isn't a CORS-safelisted header, so the page can read it
    # on a 429 only when it is exposed.
    expose_headers=["www-authenticate", "retry-after"],
    # No cookies: the token and proof are the only credentials.
    allow_credentials=False,
)
# Checks every route's policy and rate limit at startup, decides each
# request, and answers `RateLimited` with 429.
routes.install(app)
# After `install`, so it replaces the package's handler.
app.add_exception_handler(KonklavDenied, denied)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3001)
