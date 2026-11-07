"""
Pacing for FastAPI: answer chosen routes no sooner than a floor plus or
minus a random jitter (`konklav_relying.pacing`).

`RoutePacing` is a dependency, declared on routes, routers, `include_router`
or the application, before any `RoutePolicy`:

```python
from datetime import timedelta

from konklav_relying import Pacing
from konklav_fastapi import RoutePacing, RoutePolicy

pacing = Pacing(floor=timedelta(milliseconds=800), jitter=timedelta(milliseconds=200))


@router.post("/invites", dependencies=[RoutePacing(pacing), RoutePolicy(tenant_actions={"member:invite"})])
async def invite(body: Invite) -> Invited: ...
```

It is a `yield` dependency with `scope="function"`: its wait starts when
FastAPI resolves it and ends after the handler, also when the handler or a
later dependency raises (`KonklavDenied`, `RateLimited`, `HTTPException`,
a validation error of a parameter), and before the response is sent.

It can't pace what FastAPI answers before resolving dependencies: a body
it can't parse (malformed JSON, 422, or a form it can't read, 400). Nor
can it pace an unknown path (404) or method (405), or anything middleware
answers. `PacingMiddleware` paces every answer for the paths it is given:

```python
app.add_middleware(PacingMiddleware, pacing=pacing, paths={"/invites", "/password-resets"})
```
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Collection

from fastapi.params import Depends
from fastapi.requests import HTTPConnection
from konklav_relying.pacing import Pacing, paced
from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = ["PacingMiddleware", "RoutePacing"]


# r[impl item.py-fastapi.route-pacing]
# r[impl item.py-fastapi.route-pacing.nested]
class RoutePacing(Depends):
    """
    Paces the HTTP requests of the routes it is declared on, from when
    FastAPI resolves it until before the response is sent. Declare it before
    the routes' `RoutePolicy` and `RouteRateLimit`, so that denials are
    paced too: startup validation refuses one FastAPI resolves after the
    route's policy is evaluated.

    Each `RoutePacing` waits on its own, so a route under several waits for
    the longest. Websocket connections aren't paced.
    """

    pacing: Pacing

    def __init__(self, pacing: Pacing) -> None:
        async def paced_route(connection: HTTPConnection) -> AsyncIterator[None]:
            if connection.scope["type"] != "http":
                yield
                return
            async with paced(pacing):
                yield

        # Not cached: each declaration waits on its own.
        super().__init__(dependency=paced_route, use_cache=False, scope="function")
        object.__setattr__(self, "pacing", pacing)

    def __repr__(self) -> str:
        return f"RoutePacing({self.pacing!r})"


# r[impl item.py-fastapi.pacing-middleware]
class PacingMiddleware:
    """
    ASGI middleware pacing every answer to HTTP requests whose path is one
    of `paths` (compared exactly with `request.url.path`): it holds back the
    start of the response until the wait is done, including for answers
    FastAPI gives before any dependency runs and for unhandled errors.
    Cancellation isn't paced, as with `paced`.
    """

    def __init__(self, app: ASGIApp, *, pacing: Pacing, paths: Collection[str]) -> None:
        if isinstance(paths, str):
            raise TypeError("paths takes a collection of paths, not a string")
        self.app = app
        self.pacing = pacing
        self.paths = frozenset(paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] not in self.paths:
            await self.app(scope, receive, send)
            return
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.pacing.delay().total_seconds()
        started = False

        async def wait() -> None:
            nonlocal started
            started = True
            if (remaining := deadline - loop.time()) > 0:
                await asyncio.sleep(remaining)

        async def paced_send(message: Message) -> None:
            if message["type"] == "http.response.start" and not started:
                await wait()
            await send(message)

        try:
            await self.app(scope, receive, paced_send)
        except Exception:
            # The server answers an unhandled error with a 500: pace that too.
            if not started:
                await wait()
            raise

    def __repr__(self) -> str:
        return f"PacingMiddleware(pacing={self.pacing!r}, paths={sorted(self.paths)!r})"
