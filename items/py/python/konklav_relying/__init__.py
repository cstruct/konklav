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
    audience="api",
)
await client.start()
decision = await client.decide(token, {"tenant": ["workspace:read"]})
if decision["decision"] != "allow":
    ...
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
from collections.abc import Mapping
from typing import Any

import httpx

from konklav_relying._core import Core

__all__ = ["KonklavError", "Core", "RelyingClient"]

_log = logging.getLogger(__name__)

Decision = dict[str, Any]


class KonklavError(Exception):
    """Konklav could not be reached or answered with an error. Treat as deny."""


def _now() -> int:
    return time.time_ns() // 1_000_000


class RelyingClient:
    def __init__(
        self,
        *,
        relying_url: str,
        subject_url: str,
        key_id: str,
        secret: str,
        issuer: str,
        audience: str,
        http: httpx.AsyncClient | None = None,
        **config: Any,
    ) -> None:
        self._relying_url = relying_url.rstrip("/")
        self._subject_url = subject_url.rstrip("/")
        self._key_id = key_id
        self._secret = secret
        self._http = http or httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None))
        self._core = Core(json.dumps({"issuer": issuer, "audience": audience, **config}))
        # Decisions are synchronous calls into Rust; the lock only guards
        # against threads sharing one client.
        self._lock = threading.Lock()
        self._token: tuple[str, int] | None = None
        self._token_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._tasks: list[asyncio.Task[None]] = []

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        """Start following the feed and refreshing caches in the background."""
        self._tasks = [
            asyncio.create_task(self._run_feed(), name="konklav-feed"),
            asyncio.create_task(self._run_work(), name="konklav-work"),
        ]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks = []

    def is_trusted(self) -> bool:
        with self._lock:
            return self._core.is_trusted(_now())

    # -- decisions --------------------------------------------------------

    async def decide(self, token: str, requirements: Mapping[str, Any]) -> Decision:
        """
        Decide `requirements` for an access token presented to this system.

        Returns a decision such as `{"decision": "allow"}`. Raises
        `KonklavError` when no decision can be reached; callers must deny.
        """
        encoded = json.dumps(requirements)
        for _ in range(4):
            with self._lock:
                outcome = json.loads(self._core.decide(token, encoded, _now()))
            if outcome["outcome"] == "decided":
                return outcome["decision"]
            needs = outcome["needs"]
            if any(need["need"] == "check" for need in needs):
                return await self._check(token, requirements)
            await asyncio.gather(*(self._fetch(need) for need in needs))
        raise KonklavError("could not reach a decision")

    async def verify(self, token: str) -> dict[str, Any] | None:
        """
        Verify a token and its session; return its claims, or None if it is
        not valid. Raises `KonklavError` when it can't be verified now.
        """
        for _ in range(4):
            with self._lock:
                outcome = json.loads(self._core.verify(token, _now()))
            if outcome["outcome"] == "verified":
                return outcome["claims"]
            if outcome["outcome"] == "invalid":
                return None
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

    async def _check(self, token: str, requirements: Mapping[str, Any]) -> Decision:
        headers = {"authorization": f"Bearer {await self._bearer()}"}
        response = await self._http.post(
            f"{self._relying_url}/v1/check",
            json={"token": token, "requirements": requirements},
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
                    with self._lock:
                        if data:
                            self._core.on_feed_event("".join(data), _now())
                        else:
                            # A heartbeat comment.
                            self._core.on_feed_activity(_now())
                    data = []
                    self._wake.set()


def _checked(response: httpx.Response) -> httpx.Response:
    if response.is_success:
        return response
    raise KonklavError(f"konklav answered {response.status_code}: {response.text}")
