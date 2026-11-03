# Generated from ../_async by tools/generate.py; don't edit.
"""The control-plane client."""

from __future__ import annotations

from collections.abc import Iterator, Callable, Mapping
from types import TracebackType
from typing import Any

import httpx

from .. import _backend
from .._backend import SyncToken
from .._common import Written, base, delay, retryable, written
from ..errors import KonklavError, from_response
from .auth import Auth, resolve

DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3


class ControlPlaneClient:
    """A client for Konklav's control-plane surface.

    `url` is the surface's base URL, without `/v1`; a path prefix it has,
    such as a proxy's, is kept. `auth` is a `BearerToken`, a `SecretKey`
    or a function returning the token to send. Pass `http` to send through
    your own `httpx` client; otherwise the client makes one with `timeout`
    and closes it when the client is closed. `retries` is how many times a failed request
    is sent again, where it is safe to; `0` turns retries off.
    """

    # r[impl item.py-control-plane.injectable-http]
    # r[impl item.py-control-plane.explicit-config]
    def __init__(
        self,
        url: str,
        *,
        auth: Auth | Callable[[], SyncToken],
        http: httpx.Client | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        if retries < 0:
            raise ValueError("retries can't be negative")
        self._url = f"{base(url)}/v1"
        self._auth = resolve(auth)
        self._owns_http = http is None
        # The environment holds no configuration for this client.
        self._http = http if http is not None else httpx.Client(timeout=timeout, trust_env=False)
        self._retries = retries

    def __enter__(self) -> ControlPlaneClient:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Closes the `httpx` client, unless it was passed in."""
        if self._owns_http:
            self._http.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Sends a request to `path` under `/v1` and returns its decoded
        JSON body, or `None` when it has none."""
        response = self._send(method, f"{self._url}{path}", json=json, params=params)
        return response.json() if response.content else None

    def _write(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        create: bool = False,
    ) -> Written[Any]:
        """Sends a write and splits the cursor off its result."""
        response = self._send(method, f"{self._url}{path}", json=json, params=params)
        return written(response, create=create)

    # r[impl item.py-control-plane.paging]
    def _pages(
        self, path: str, key: str, params: Mapping[str, Any] | None = None
    ) -> Iterator[Any]:
        """Every item of a paged list, page after page."""
        query = {name: value for name, value in (params or {}).items() if value is not None}
        while True:
            page = self.request("GET", path, params=query)
            for item in page[key]:
                yield item
            if page.get("next") is None:
                return
            query["before"] = page["next"]

    def _send(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        authenticate: bool = True,
    ) -> httpx.Response:
        """Sends a request, logging in again once and retrying as allowed."""
        attempt = 0
        relogged = False
        while True:
            headers = {}
            if authenticate:
                headers["authorization"] = f"Bearer {self._auth.token(self)}"
            cause: Exception | None = None
            try:
                response = self._http.request(
                    method, url, json=json, params=params, headers=headers
                )
            except httpx.TransportError as error:
                failure = KonklavError(f"Konklav couldn't be reached: {error}")
                cause = error
            else:
                if response.is_success:
                    return response
                failure = from_response(response)
                # r[impl item.py-control-plane.auth-relogin]
                if (
                    authenticate
                    and failure.code == "UNAUTHENTICATED"
                    and not relogged
                    and self._auth.invalidate()
                ):
                    relogged = True
                    continue
            if attempt >= self._retries or not retryable(method, failure):
                raise failure from cause
            _backend.sync_sleep(delay(attempt, failure))
            attempt += 1
