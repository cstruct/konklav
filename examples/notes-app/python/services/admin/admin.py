"""The admin page, on http://localhost:4000: frontend and backend in one.

A backend-for-frontend. It is a confidential OIDC client (`admin`): it signs
people in through Konklav with the code flow, PKCE and DPoP, and keeps the
tokens and the DPoP key in this process. The browser gets only an opaque,
HttpOnly session cookie; no token ever reaches it.

Every API request is decided by `konklav-relying`: the backend presents the
admin's DPoP token with a proof from its own key, and the request goes
through only if the person holds `admin:access`. A role taken away, or a
session ended anywhere (signing out of the app ends this one too), is
refused within about a second.

What admins do here goes through the control-plane client as the
`admin-api` service principal, which may manage people, roles and sessions
and nothing else. Those writes are rate limited per client address.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from secrets import token_urlsafe
from typing import Any
from urllib.parse import urlencode

import httpx
import redis.asyncio
import uvicorn
from konklav_control_plane import ControlPlaneClient, KonklavError as ControlError, SecretKey
from konklav_fastapi import KonklavRoutes, handle_rate_limited
from konklav_relying import KonklavError, RateLimit, RateLimited, RateLimitWindow, RelyingClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from example import WEB, WEB_ROOT, DpopKey, b64url, claims_of, secrets, security_headers, split_key

PAGES = WEB_ROOT / "admin"
ISSUER = os.environ["ISSUER"]
PUBLIC_URL = os.environ["PUBLIC_URL"]
SUBJECT_URL = os.environ["KONKLAV_SUBJECT_URL"]
CLIENT_ID = "admin"
REDIRECT_URI = f"{PUBLIC_URL}/callback"
MANAGED_ROLES = ["member", "editor", "admin"]

# Cookies on localhost are shared by every port, so the names are specific.
SESSION_COOKIE = "example_admin_session"
LOGIN_COOKIE = "example_admin_login"
# Sent by the page's scripts on every write. Another site can't send it
# without a CORS preflight, which this origin never answers.
CSRF_HEADER = "x-example-admin"

CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

SECRETS = secrets()
http = httpx.AsyncClient(timeout=15.0)

# One service principal for both: following the feed, and the control plane.
key_id, secret = split_key(SECRETS["admin_api_key"])
relying = RelyingClient(
    relying_url=os.environ["KONKLAV_RELYING_URL"],
    subject_url=SUBJECT_URL,
    key_id=key_id,
    secret=secret,
    issuer=ISSUER,
    # The `admin` OIDC client's tokens carry this audience.
    audience="admin",
)
control = ControlPlaneClient(
    os.environ["KONKLAV_CONTROL_URL"],
    auth=SecretKey(subject_url=SUBJECT_URL, key_id=key_id, secret=secret),
)


def internal(url: str) -> str:
    """Konklav's public endpoint URLs, as this container reaches them. The
    proofs keep naming the public URL, which is what Konklav checks."""
    return url.replace(ISSUER, SUBJECT_URL, 1)


ENDPOINTS: dict[str, str] = {}

# Ten writes at once, then one every 6 seconds, per client address: making
# people and changing roles is rare work, and a script doing it fast is not
# an admin. Shared through Valkey like the app backend's limit, though this
# service runs once.
admin_writes = RateLimit(
    "notes-app.admin-writes",
    [RateLimitWindow(size=10, period=timedelta(minutes=1))],
    redis=redis.asyncio.Redis.from_url(os.environ["REDIS_URL"]),
    secret=SECRETS["rate_limit_secret"].encode(),
)
# Only for `client_address`. No proxy stands in front of this service, so
# `trusted_proxies` stays empty and the address is the connection's peer;
# behind one, list it here and the address comes from `X-Forwarded-For`.
addresses = KonklavRoutes(trusted_proxies=[])


# --- Server-side sessions ----------------------------------------------------


@dataclass
class Session:
    """One signed-in admin. Lives in this process only, so a restart signs
    everyone out of the admin page (but not of the login page)."""

    key: DpopKey
    access_token: str
    refresh_token: str | None
    id_token: str
    expires_at: float
    sub: str
    email: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class PendingLogin:
    key: DpopKey
    verifier: str
    nonce: str
    created: float = field(default_factory=time.monotonic)


SESSIONS: dict[str, Session] = {}
PENDING: dict[str, PendingLogin] = {}


class Refused(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status, self.message = status, message


async def token_request(key: DpopKey, params: dict[str, str]) -> dict[str, Any]:
    """A token request authenticated with the client secret and carrying a
    proof of `key`, so the tokens are bound to it."""
    endpoint = ENDPOINTS["token_endpoint"]
    response = await http.post(
        internal(endpoint),
        data=params,
        auth=(CLIENT_ID, SECRETS["admin_client_secret"]),
        headers={"dpop": key.proof("POST", endpoint)},
    )
    body = response.json()
    if not response.is_success:
        raise Refused(401, body.get("error_description") or body.get("error", "token request failed"))
    if body["token_type"] != "DPoP":
        raise Refused(500, f"expected DPoP tokens, got {body['token_type']}")
    return body


async def fresh(session: Session) -> None:
    """Refreshes the access token when it is about to expire."""
    async with session.lock:
        if session.expires_at - time.time() > 30:
            return
        if not session.refresh_token:
            raise Refused(401, "your sign-in has expired")
        body = await token_request(
            session.key, {"grant_type": "refresh_token", "refresh_token": session.refresh_token}
        )
        session.access_token = body["access_token"]
        session.refresh_token = body.get("refresh_token", session.refresh_token)
        session.expires_at = time.time() + body["expires_in"]


async def authorize(request: Request, *, require_admin: bool = True) -> tuple[Session, bool]:
    """The request's session, and whether its person may use the admin page.

    The decision comes from the relying client, with the session's token
    under the `DPoP` scheme and a proof for this request signed by the
    session's key. The browser never sees either.
    """
    if request.method != "GET":
        if CSRF_HEADER not in request.headers or request.headers.get("origin") != PUBLIC_URL:
            raise Refused(403, "cross-site request refused")
        # Counted before the session is looked up, so refused writes count too.
        # Raises `RateLimited`, which the app answers with 429.
        await admin_writes.add(addresses.client_address(request) or "unknown")
    sid = request.cookies.get(SESSION_COOKIE)
    session = SESSIONS.get(sid or "")
    if session is None:
        raise Refused(401, "sign in first")
    try:
        await fresh(session)
    except Refused:
        SESSIONS.pop(sid, None)
        raise
    url = f"{PUBLIC_URL}{request.url.path}"
    try:
        decision = await relying.decide_request(
            authorization=f"DPoP {session.access_token}",
            dpop=session.key.proof(request.method, url, session.access_token),
            method=request.method,
            url=url,
            requirements={"global": ["admin:access"], "token_kinds": ["identity"]},
        )
    except KonklavError:
        raise Refused(503, "authorization is unavailable; try again") from None
    if decision.get("reason") == "invalid_token":
        # Revoked: signed out at the login page or the app, or by an admin.
        SESSIONS.pop(sid, None)
        raise Refused(401, "your session has ended")
    allowed = decision["decision"] == "allow"
    if require_admin and not allowed:
        raise Refused(403, "you need the admin role to use this page")
    return session, allowed


# --- Signing in and out ------------------------------------------------------


async def login(request: Request) -> Response:
    """Starts a sign-in. With `?silent`, asks for `prompt=none`: single sign-on
    when the person is signed in at the login page, `login_required` if not."""
    state = token_urlsafe(16)
    pending = PendingLogin(DpopKey(), token_urlsafe(32), token_urlsafe(16))
    # Forget logins that were never finished.
    for stale in [s for s, p in PENDING.items() if time.monotonic() - p.created > 600]:
        del PENDING[stale]
    PENDING[state] = pending
    query = urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid email",
            "state": state,
            "nonce": pending.nonce,
            "code_challenge": b64url(hashlib.sha256(pending.verifier.encode()).digest()),
            "code_challenge_method": "S256",
            # Binds the code to the key, as for the token request.
            "dpop_jkt": pending.key.thumbprint(),
            **({"prompt": "none"} if "silent" in request.query_params else {}),
        }
    )
    response = RedirectResponse(f"{ENDPOINTS['authorization_endpoint']}?{query}", status_code=303)
    # Ties the callback to the browser that started the login.
    response.set_cookie(LOGIN_COOKIE, state, max_age=600, httponly=True, samesite="lax", path="/callback")
    return response


async def callback(request: Request) -> Response:
    state = request.query_params.get("state", "")
    pending = PENDING.pop(state, None)
    if pending is None or request.cookies.get(LOGIN_COOKIE) != state:
        return JSONResponse({"message": "this sign-in wasn't started in this browser"}, status_code=400)
    if request.query_params.get("iss") != ISSUER:
        return JSONResponse({"message": "the response came from another issuer"}, status_code=400)
    if error := request.query_params.get("error"):
        return RedirectResponse(f"/?error={error}", status_code=303)

    body = await token_request(
        pending.key,
        {
            "grant_type": "authorization_code",
            "code": request.query_params.get("code", ""),
            "redirect_uri": REDIRECT_URI,
            "code_verifier": pending.verifier,
        },
    )
    # Straight from the token endpoint over a connection this server made,
    # so its signature needs no further check (OIDC Core 3.1.3.7).
    identity = claims_of(body["id_token"])
    if identity.get("nonce") != pending.nonce or identity.get("aud") not in (CLIENT_ID, [CLIENT_ID]):
        return JSONResponse({"message": "the ID token doesn't match this sign-in"}, status_code=400)

    userinfo_url = ENDPOINTS["userinfo_endpoint"]
    userinfo = await http.get(
        internal(userinfo_url),
        headers={
            "authorization": f"DPoP {body['access_token']}",
            "dpop": pending.key.proof("GET", userinfo_url, body["access_token"]),
        },
    )
    sid = token_urlsafe(32)
    SESSIONS[sid] = Session(
        key=pending.key,
        access_token=body["access_token"],
        refresh_token=body.get("refresh_token"),
        id_token=body["id_token"],
        expires_at=time.time() + body["expires_in"],
        sub=identity["sub"],
        email=userinfo.json().get("email", identity["sub"]) if userinfo.is_success else identity["sub"],
    )
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(LOGIN_COOKIE, path="/callback")
    response.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="strict", path="/")
    return response


async def logout(request: Request) -> Response:
    if CSRF_HEADER not in request.headers or request.headers.get("origin") != PUBLIC_URL:
        return JSONResponse({"message": "cross-site request refused"}, status_code=403)
    session = SESSIONS.pop(request.cookies.get(SESSION_COOKIE, ""), None)
    redirect = "/"
    if session:
        # Ends the sign-in at the login page too, and the app's session.
        query = urlencode(
            {"client_id": CLIENT_ID, "id_token_hint": session.id_token, "post_logout_redirect_uri": f"{PUBLIC_URL}/"}
        )
        redirect = f"{ENDPOINTS['end_session_endpoint']}?{query}"
    response = JSONResponse({"redirect": redirect})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# --- The admin API -----------------------------------------------------------


async def me(request: Request) -> Response:
    session, admin = await authorize(request, require_admin=False)
    return JSONResponse({"sub": session.sub, "email": session.email, "admin": admin})


async def role_ids() -> dict[str, str]:
    return {role["id"]: role["key"] for role in await control.roles.list("root")}


async def list_users(request: Request) -> Response:
    await authorize(request)
    keys = await role_ids()
    users = []
    async for subject in control.subjects.iter(kind="human"):
        detail, assignments = await asyncio.gather(
            control.subjects.get(subject["id"]), control.assignments.list_global(subject["id"])
        )
        users.append(
            {
                "id": subject["id"],
                "state": subject["state"],
                "emails": [
                    c["identifier"]
                    for c in detail["credentials"]
                    if c["kind"] == "password" and not c["revoked_at"]
                ],
                "roles": sorted(keys.get(a["role_id"], "?") for a in assignments),
            }
        )
    users.sort(key=lambda user: user["emails"][0] if user["emails"] else user["id"])
    return JSONResponse({"users": users, "roles": MANAGED_ROLES})


async def settled(written: Any) -> None:
    """Waits until the relying client has seen the write, so the next
    decision anywhere it is used reflects it (read-your-writes)."""
    if written.cursor is not None:
        await relying.await_cursor(written.cursor)


async def create_user(request: Request) -> Response:
    await authorize(request)
    body = await request.json()
    email, password = str(body.get("email", "")).strip(), str(body.get("password", ""))
    if not email or len(password) < 12:
        raise Refused(400, "give an email and a password of at least 12 characters")
    subject = str(uuid.uuid4())
    await control.subjects.create(subject, {"kind": "human"})
    await control.credentials.create(subject, {"kind": "password", "identifier": email, "password": password})
    await settled(await control.assignments.assign_global(subject, {"role": "member"}))
    return JSONResponse({"id": subject}, status_code=201)


async def set_role(request: Request) -> Response:
    session, _ = await authorize(request)
    subject, role = request.path_params["subject"], request.path_params["role"]
    if role not in MANAGED_ROLES:
        raise Refused(400, f"this page manages only {', '.join(MANAGED_ROLES)}")
    if request.method == "PUT":
        await settled(await control.assignments.assign_global(subject, {"role": role}))
        return JSONResponse({"ok": True})
    if subject == session.sub and role == "admin":
        raise Refused(400, "you can't take away your own admin role")
    keys = await role_ids()
    for assignment in await control.assignments.list_global(subject):
        if keys.get(assignment["role_id"]) == role:
            await settled(await control.assignments.unassign(assignment["id"]))
    return JSONResponse({"ok": True})


async def sign_out_user(request: Request) -> Response:
    session, _ = await authorize(request)
    subject = request.path_params["subject"]
    written = await control.sessions.revoke(
        {"subject": subject, "reason": "signed out by an admin"}
    )
    await settled(written)
    return JSONResponse({"ok": True, "you": subject == session.sub})


async def set_state(request: Request) -> Response:
    session, _ = await authorize(request)
    subject, action = request.path_params["subject"], request.path_params["action"]
    if action not in ("disable", "enable"):
        raise Refused(404, "not found")
    if action == "disable":
        if subject == session.sub:
            raise Refused(400, "you can't disable yourself")
        await settled(await control.subjects.disable(subject))
    else:
        await settled(await control.subjects.enable(subject))
    return JSONResponse({"ok": True})


def handle(endpoint):
    async def wrapped(request: Request) -> Response:
        try:
            return await endpoint(request)
        except Refused as refused:
            return JSONResponse({"message": refused.message}, status_code=refused.status)
        except ControlError as error:
            return JSONResponse({"message": error.message}, status_code=error.status or 502)

    return wrapped


async def page(_: Request) -> Response:
    return FileResponse(PAGES / "admin.html", headers=security_headers(CSP))


@contextlib.asynccontextmanager
async def lifespan(_: Starlette):
    discovery = (await http.get(f"{SUBJECT_URL}/.well-known/openid-configuration")).json()
    ENDPOINTS.update(discovery)
    await relying.start()
    for _ in range(300):
        if relying.is_trusted():
            break
        await asyncio.sleep(0.1)
    print("following Konklav's change feed", flush=True)
    yield
    await relying.stop()
    await control.aclose()


app = Starlette(
    routes=[
        Route("/", page),
        Route("/login", login),
        Route("/callback", handle(callback)),
        Route("/logout", logout, methods=["POST"]),
        Route("/api/me", handle(me)),
        Route("/api/users", handle(list_users), methods=["GET"]),
        Route("/api/users", handle(create_user), methods=["POST"]),
        Route("/api/users/{subject}/roles/{role}", handle(set_role), methods=["PUT", "DELETE"]),
        Route("/api/users/{subject}/sign-out", handle(sign_out_user), methods=["POST"]),
        Route("/api/users/{subject}/{action:str}", handle(set_state), methods=["POST"]),
        Mount("/static", StaticFiles(directory=PAGES)),
        Mount("/shared", StaticFiles(directory=WEB)),
    ],
    lifespan=lifespan,
    # konklav-fastapi's handler is a plain Starlette one: 429, `Retry-After`.
    exception_handlers={RateLimited: handle_rate_limited},
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=4000)
