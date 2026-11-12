"""
Decide Konklav authorization locally.

`RelyingClient` wraps the relying core (written in Rust, shared with every
other binding) and does its I/O with httpx on asyncio: it logs in as a
service principal, follows the change feed, keeps caches warm in the
background, and answers `decide` locally, falling back to Konklav's check
API whenever the core says its caches can't be trusted.

```python
client = RelyingClient(
    relying_url="https://konklav:8081",
    subject_url="https://konklav:8080",
    key_id=key_id,
    secret=secret,
    issuer="https://auth.example",
    audiences={"api", "app"},
)
await client.start()
decision = await client.decide(token, {"tenant": ["project:read"]})
if decision["decision"] != "allow":
    ...
```

For sender-constrained (DPoP) tokens, pass the request's raw headers and
the public URL the client addressed (behind a proxy, not the upstream URL):

```python
decision = await client.decide_request(
    authorization=request.headers["authorization"],
    dpop=request.headers.get("dpop"),
    method=request.method,
    url=public_url,
    requirements={"tenant": ["project:read"]},
)
```

`audiences` are the audiences this relying system accepts: a token is
valid for any of them, and `AccessToken.aud` says which it carries.
`audience="api"` is short for `audiences={"api"}`.

A decision denied with reason `invalid_dpop_proof` should be answered with
401 and `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.

Route policies (`Policy`, in `konklav_relying.policy`) declare an
operation's requirements once per route or router and resolve them per
request; `decide_typed`, `decide_request_typed`, `verify_typed` and
`verify_request_typed` return `Decision` and `AccessToken` instead of JSON:

```python
policy = Policy.merge(router_policy, route_policy)
decision = await client.decide_typed(token, policy.requirements({"project": project_id}))
if not decision.allowed:
    ...
```

`RateLimit` (in `konklav_relying.rate_limit`) bounds how often events may
happen per key, through a Redis rate-limit store with the `redis` extra
and in memory always:

```python
login = RateLimit("login", [RateLimitWindow(size=5, period=timedelta(minutes=1))])
await login.add(email)  # raises RateLimited
```

A relying system that keeps data about subjects hears of erasures through
`on_erasure`, and catches up with `erased_subjects`:

```python
async def on_erasure(notice: Erased | ErasuresMissed) -> None:
    if isinstance(notice, Erased):
        await delete_everything_about(notice.subject)
    else:
        for erased in await client.erased_subjects(since=my_stored_watermark()):
            await delete_everything_about(erased.subject)

client = RelyingClient(..., on_erasure=on_erasure)
```
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import threading
import time
import urllib.parse
from collections.abc import Awaitable, Callable, Collection, Mapping
from typing import Any

import httpx

from konklav_relying._core import Core
from konklav_relying.fake_ids import fake_uuid7
from konklav_relying.pacing import Pacing, paced
from konklav_relying.policy import MissingScopeId, Policy, PolicyError, Requirements, StepUp
from konklav_relying.rate_limit import RateLimit, RateLimited, RateLimitWindow
from konklav_relying.results import (
    AcceptedRequest,
    AccessToken,
    Actor,
    Confirmation,
    Decision,
    DenyReason,
    Erased,
    ErasureNotice,
    ErasuresMissed,
    Obligation,
    erasure_notice,
)

__all__ = [
    "AcceptedRequest",
    "AccessToken",
    "Actor",
    "Confirmation",
    "Core",
    "Decision",
    "DenyReason",
    "Erased",
    "ErasureNotice",
    "ErasuresMissed",
    "InvalidDpopProof",
    "KonklavError",
    "MissingScopeId",
    "Obligation",
    "Pacing",
    "Policy",
    "PolicyError",
    "RateLimit",
    "RateLimitWindow",
    "RateLimited",
    "RelyingClient",
    "Requirements",
    "StepUp",
    "fake_uuid7",
    "paced",
]

_log = logging.getLogger(__name__)

_DecisionJson = dict[str, Any]


class KonklavError(Exception):
    """Konklav could not be reached or answered with an error. Treat as deny."""


class InvalidDpopProof(Exception):
    """
    The token was refused for its DPoP proof or authorization scheme.
    Answer with 401 and `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
    """


def _now() -> int:
    return time.time_ns() // 1_000_000


def _presented(authorization: str, dpop: str | None, method: str, url: str) -> str:
    return json.dumps(
        {
            "authorization": authorization,
            "dpop": dpop,
            "request": {"method": method, "url": url},
        }
    )


# r[impl item.py.audiences]
def _audiences(audience: str | None, audiences: Collection[str] | None) -> list[str]:
    if (audience is None) == (audiences is None):
        raise TypeError("pass either audience or audiences")
    if audiences is None:
        assert audience is not None
        return [audience]
    if isinstance(audiences, str):
        raise TypeError("audiences takes a collection of strings, not a string")
    if not audiences:
        raise ValueError("audiences is empty, so no token would be accepted")
    return sorted(set(audiences))


def _token_of(authorization: str) -> str:
    """The token after the scheme, for the check API."""
    return authorization.partition(" ")[2].strip()


class RelyingClient:
    def __init__(
        self,
        *,
        relying_url: str,
        subject_url: str,
        key_id: str,
        secret: str,
        issuer: str,
        audience: str | None = None,
        audiences: Collection[str] | None = None,
        http: httpx.AsyncClient | None = None,
        on_erasure: Callable[[ErasureNotice], Awaitable[None]] | None = None,
        **config: Any,
    ) -> None:
        """
        Pass the accepted audiences as `audiences`, or one as `audience`.
        `config` tunes the relying core (`Config` in the Rust crate), such
        as `entitlement_ttl_ms`.

        `on_erasure` is awaited, one notice at a time, with each `Erased`
        subject the change feed reports, so the relying system can remove
        its own data about it, and with `ErasuresMissed` when some may have
        been missed, which includes every start: the client can't know
        what happened while it wasn't running. The same erasure may arrive
        more than once. A notice whose handler raises is logged and not
        repeated, and notices are lost with the process, so a relying
        system that must not miss one keeps the time it has handled
        erasures up to in its own storage and reads `erased_subjects` from
        there on `ErasuresMissed`.
        """
        self._relying_url = relying_url.rstrip("/")
        self._subject_url = subject_url.rstrip("/")
        self._key_id = key_id
        self._secret = secret
        self._http = http or httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None))
        self._audiences = _audiences(audience, audiences)
        self._core = Core(json.dumps({"issuer": issuer, "audiences": self._audiences, **config}))
        # Decisions are synchronous calls into Rust; the lock only guards
        # against threads sharing one client.
        self._lock = threading.Lock()
        self._token: tuple[str, int] | None = None
        self._token_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._tasks: list[asyncio.Task[None]] = []
        self._on_erasure = on_erasure
        self._erasures: asyncio.Queue[ErasureNotice] = asyncio.Queue()

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        """Start following the feed and refreshing caches in the background."""
        self._tasks = [
            asyncio.create_task(self._run_feed(), name="konklav-feed"),
            asyncio.create_task(self._run_work(), name="konklav-work"),
        ]
        if self._on_erasure is not None:
            self._tasks.append(asyncio.create_task(self._run_erasures(self._on_erasure), name="konklav-erasures"))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks = []

    @property
    def audiences(self) -> frozenset[str]:
        """The audiences this client accepts tokens for."""
        return frozenset(self._audiences)

    def is_trusted(self) -> bool:
        with self._lock:
            return self._core.is_trusted(_now())

    # -- decisions --------------------------------------------------------

    async def decide(self, token: str, requirements: Mapping[str, Any]) -> _DecisionJson:
        """
        Decide `requirements` for a bearer access token presented to this
        system. A sender-constrained (DPoP) token is denied: use
        `decide_request`.

        Returns a decision such as `{"decision": "allow"}`. Raises
        `KonklavError` when no decision can be reached; callers must deny.
        """
        encoded = json.dumps(requirements)
        return await self._decide(
            token, requirements, lambda: self._core.decide(token, encoded, _now())
        )

    async def decide_request(
        self,
        *,
        authorization: str,
        dpop: str | None,
        method: str,
        url: str,
        requirements: Mapping[str, Any],
    ) -> _DecisionJson:
        """
        Decide `requirements` for a request's raw `Authorization` and `DPoP`
        headers. `url` is the URL the client addressed. Bearer and
        sender-constrained tokens both work.
        """
        presented = _presented(authorization, dpop, method, url)
        encoded = json.dumps(requirements)
        return await self._decide(
            _token_of(authorization),
            requirements,
            lambda: self._core.decide_presented(presented, encoded, _now()),
        )

    async def _decide(
        self, token: str, requirements: Mapping[str, Any], ask: Callable[[], str]
    ) -> _DecisionJson:
        for _ in range(4):
            with self._lock:
                outcome = json.loads(ask())
            if outcome["outcome"] == "decided":
                return outcome["decision"]
            needs = outcome["needs"]
            if any(need["need"] == "check" for need in needs):
                # The core has checked any DPoP proof; the check API takes
                # the token alone.
                return await self._check(token, requirements)
            await asyncio.gather(*(self._fetch(need) for need in needs))
        raise KonklavError("could not reach a decision")

    # -- typed results ----------------------------------------------------

    # r[impl item.py.typed.compatible]
    async def decide_typed(self, token: str, requirements: Mapping[str, Any]) -> Decision:
        """`decide`, returning a `Decision`."""
        return Decision.from_json(await self.decide(token, requirements))

    async def decide_request_typed(
        self,
        *,
        authorization: str,
        dpop: str | None,
        method: str,
        url: str,
        requirements: Mapping[str, Any],
    ) -> Decision:
        """`decide_request`, returning a `Decision`."""
        return Decision.from_json(
            await self.decide_request(
                authorization=authorization, dpop=dpop, method=method, url=url, requirements=requirements
            )
        )

    async def verify_typed(self, token: str) -> AccessToken | None:
        """`verify`, returning an `AccessToken`."""
        claims = await self.verify(token)
        return None if claims is None else AccessToken.from_claims(claims)

    async def verify_request_typed(
        self, *, authorization: str, dpop: str | None, method: str, url: str
    ) -> AccessToken | None:
        """`verify_request`, returning an `AccessToken`."""
        claims = await self.verify_request(authorization=authorization, dpop=dpop, method=method, url=url)
        return None if claims is None else AccessToken.from_claims(claims)

    # r[impl relying.verify.accepted-presentation]
    # r[impl item.py.accepted-request]
    async def accept_request(
        self, *, authorization: str, dpop: str | None, method: str, url: str
    ) -> AcceptedRequest | None:
        """
        `verify_request_typed` for a request you decide afterwards: verifies
        the token, its session and its DPoP proof, and returns the verified
        token with the presentation to pass to `decide_accepted`, which
        doesn't check the proof again. Returns None if the token isn't
        valid; raises `InvalidDpopProof` and `KonklavError` as
        `verify_request` does.
        """
        presented = _presented(authorization, dpop, method, url)
        token = _token_of(authorization)
        for _ in range(4):
            with self._lock:
                outcome = json.loads(self._core.accept_presented(presented, _now()))
            match outcome["outcome"]:
                case "accepted":
                    claims = outcome["claims"]
                case "check":
                    claims = await self._verify_centrally(token)
                    if claims is None:
                        return None
                case "invalid":
                    return None
                case "invalid_proof":
                    raise InvalidDpopProof("the DPoP proof or scheme is invalid")
                case _:
                    await asyncio.gather(*(self._fetch(need) for need in outcome["needs"]))
                    continue
            return AcceptedRequest(
                token=AccessToken.from_claims(claims),
                presentation=json.dumps(outcome["presentation"]),
                access_token=token,
            )
        raise KonklavError("could not verify the token")

    async def decide_accepted(self, accepted: AcceptedRequest, requirements: Mapping[str, Any]) -> _DecisionJson:
        """
        Decide `requirements` for a request `accept_request` accepted, once.
        Its session is checked again; its proof isn't. A request decided
        before, or accepted too long ago, is denied with `invalid_token`.
        """
        encoded = json.dumps(requirements)
        return await self._decide(
            accepted.access_token,
            requirements,
            lambda: self._core.decide_accepted(accepted.presentation, encoded, _now()),
        )

    async def decide_accepted_typed(self, accepted: AcceptedRequest, requirements: Mapping[str, Any]) -> Decision:
        """`decide_accepted`, returning a `Decision`."""
        return Decision.from_json(await self.decide_accepted(accepted, requirements))

    async def verify(self, token: str) -> dict[str, Any] | None:
        """
        Verify a bearer token and its session; return its claims, or None if
        it is not valid. Raises `KonklavError` when it can't be verified now,
        and `InvalidDpopProof` for a sender-constrained token: use
        `verify_request` for those.
        """
        return await self._verify(token, lambda: self._core.verify(token, _now()))

    async def verify_request(
        self, *, authorization: str, dpop: str | None, method: str, url: str
    ) -> dict[str, Any] | None:
        """
        `verify` for a request's raw `Authorization` and `DPoP` headers, like
        `decide_request`. Raises `InvalidDpopProof` when the proof or scheme
        is wrong.
        """
        presented = _presented(authorization, dpop, method, url)
        return await self._verify(
            _token_of(authorization),
            lambda: self._core.verify_presented(presented, _now()),
        )

    async def _verify(self, token: str, ask: Callable[[], str]) -> dict[str, Any] | None:
        for _ in range(4):
            with self._lock:
                outcome = json.loads(ask())
            if outcome["outcome"] == "verified":
                return outcome["claims"]
            if outcome["outcome"] == "invalid":
                return None
            if outcome["outcome"] == "invalid_proof":
                raise InvalidDpopProof("the DPoP proof or scheme is invalid")
            if any(need["need"] == "check" for need in outcome["needs"]):
                return await self._verify_centrally(token)
            await asyncio.gather(*(self._fetch(need) for need in outcome["needs"]))
        raise KonklavError("could not verify the token")

    async def _verify_centrally(self, token: str) -> dict[str, Any] | None:
        decision = await self._check(token, {"token_kinds": ["partial", "identity", "tenant", "reset_password", "invite"]})
        if decision.get("reason") == "invalid_token":
            return None
        # The check API vouched for the token; read its claims.
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))

    async def entitlements(self, subject: str, tenant: str | None) -> dict[str, Any]:
        """The entitlement set of `subject` in `tenant` (global only when None)."""
        for _ in range(3):
            with self._lock:
                outcome = json.loads(self._core.entitlements(subject, tenant, _now()))
            if outcome["outcome"] == "ready":
                return outcome["set"]
            needs = [need for need in outcome["needs"] if need["need"] != "check"]
            if not needs:
                path = f"/v1/entitlements/{subject}" + (f"/{tenant}" if tenant else "")
                return _checked(await self._get(path)).json()
            await asyncio.gather(*(self._fetch(need) for need in needs))
        raise KonklavError("could not load entitlements")

    async def events(self, after: int, kinds: list[str] | None = None, limit: int = 100) -> dict[str, Any]:
        """
        A page of the change feed after `after`: `{"events": [...], "next":
        cursor, "reset": bool}`. For consumers that keep their own cursor,
        such as a delivery worker.
        """
        query = f"?after={after}&limit={limit}"
        if kinds:
            query += "&kinds=" + ",".join(kinds)
        return _checked(await self._get(f"/v1/events/batch{query}")).json()

    async def erased_subjects(self, since: int | None = None) -> list[Erased]:
        """
        Every subject Konklav erased at or after `since` (Unix seconds), or
        ever when `None`, in the order they were erased. Unlike the feed,
        this reaches back however long the relying system was away.
        """
        erased: list[Erased] = []
        after: str | None = None
        while True:
            query = "?limit=1000"
            if since is not None:
                query += f"&since={since}"
            if after is not None:
                query += f"&after={after}"
            page = _checked(await self._get(f"/v1/erased-subjects{query}")).json()
            erased.extend(Erased.from_json(entry) for entry in page["subjects"])
            after = page.get("next")
            if after is None:
                return erased

    async def await_cursor(self, cursor: int, timeout: float = 5.0) -> bool:
        """Wait until this client reflects every change up to `cursor`."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if self._core.await_cursor(cursor):
                    return True
            self._wake.set()
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.02)

    # -- I/O --------------------------------------------------------------

    async def _bearer(self) -> str:
        async with self._token_lock:
            if self._token and self._token[1] > _now():
                return self._token[0]
            response = await self._http.post(
                f"{self._subject_url}/v1/login/secret-key",
                json={"key_id": self._key_id, "secret": self._secret},
            )
            body = _checked(response).json()
            # Renew at 80% of the lifetime.
            self._token = (body["access_token"], _now() + body["expires_in"] * 800)
            return self._token[0]

    async def _get(self, path: str) -> httpx.Response:
        headers = {"authorization": f"Bearer {await self._bearer()}"}
        return await self._http.get(f"{self._relying_url}{path}", headers=headers)

    async def _check(self, token: str, requirements: Mapping[str, Any]) -> _DecisionJson:
        headers = {"authorization": f"Bearer {await self._bearer()}"}
        response = await self._http.post(
            f"{self._relying_url}/v1/check",
            json={"token": token, "requirements": requirements, "audiences": self._audiences},
            headers=headers,
        )
        body = _checked(response).json()
        body.pop("revision", None)
        return body

    async def _fetch(self, need: Mapping[str, Any]) -> None:
        try:
            await self._fetch_inner(need)
        except Exception:
            with self._lock:
                self._core.on_fetch_failed(json.dumps(need))
            raise

    async def _fetch_inner(self, need: Mapping[str, Any]) -> None:
        kind = need["need"]
        if kind == "jwks":
            response = _checked(await self._get("/.well-known/jwks.json"))
            with self._lock:
                self._core.on_jwks(response.text, _now())
        elif kind == "session":
            response = await self._get(f"/v1/session-states/{need['session']}")
            if response.status_code == 404:
                with self._lock:
                    self._core.on_session_unknown(need["session"])
            else:
                text = _checked(response).text
                with self._lock:
                    self._core.on_session(text)
        elif kind == "entitlements":
            key = need["key"]
            path = f"/v1/entitlements/{key['subject']}"
            if key.get("tenant"):
                path += f"/{key['tenant']}"
            response = _checked(await self._get(path))
            with self._lock:
                self._core.on_entitlements(response.text, _now())
        elif kind == "registered_scope":
            kind_segment = urllib.parse.quote(need["kind"], safe="")
            id_segment = urllib.parse.quote(need["id"], safe="")
            response = await self._get(f"/v1/registered-scopes/{kind_segment}/{id_segment}")
            if response.status_code == 404:
                with self._lock:
                    self._core.on_registered_scope_unknown(need["kind"], need["id"], _now())
            else:
                text = _checked(response).text
                with self._lock:
                    self._core.on_registered_scope(text, _now())

    async def _run_work(self) -> None:
        while True:
            with self._lock:
                work = json.loads(self._core.poll_work(_now()))
            for need in work["fetch"]:
                try:
                    await self._fetch(need)
                except Exception:
                    _log.warning("background fetch failed: %s", need, exc_info=True)
            if work["fetch"]:
                continue
            wait = max(work["next_poll_at"] - _now(), 1) / 1000
            self._wake.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=wait)

    # r[impl relying.erasure.notify]
    # r[impl relying.erasure.reset]
    async def _run_erasures(self, handler: Callable[[ErasureNotice], Awaitable[None]]) -> None:
        while True:
            notice = await self._erasures.get()
            try:
                await handler(notice)
            except asyncio.CancelledError:
                raise
            except Exception:
                _log.exception("the erasure handler failed for %r", notice)

    async def _run_feed(self) -> None:
        backoff = 0.25
        while True:
            try:
                await self._follow_feed()
                backoff = 0.25
            except asyncio.CancelledError:
                raise
            except Exception:
                _log.warning("change feed disconnected", exc_info=True)
            with self._lock:
                self._core.on_feed_lost()
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 10.0)

    async def _follow_feed(self) -> None:
        headers = {"authorization": f"Bearer {await self._bearer()}"}
        with self._lock:
            cursor = self._core.feed_cursor()
        if cursor is not None:
            headers["last-event-id"] = str(cursor)
        url = f"{self._relying_url}/v1/events"
        async with self._http.stream("GET", url, headers=headers) as response:
            _checked(response)
            with self._lock:
                self._core.on_feed_connected(_now())
            self._wake.set()
            data: list[str] = []
            async for line in response.aiter_lines():
                if line.startswith("data:"):
                    data.append(line[5:].strip())
                elif line == "":
                    notice = None
                    with self._lock:
                        if data:
                            notice = self._core.on_feed_event("".join(data), _now())
                        else:
                            # A heartbeat comment.
                            self._core.on_feed_activity(_now())
                    if notice is not None and self._on_erasure is not None:
                        self._erasures.put_nowait(erasure_notice(json.loads(notice)))
                    data = []
                    self._wake.set()


def _checked(response: httpx.Response) -> httpx.Response:
    if response.is_success:
        return response
    raise KonklavError(f"konklav answered {response.status_code}: {response.text}")
