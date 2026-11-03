"""The control-plane client."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from types import TracebackType
from typing import Any

import httpx

from .. import _backend
from .._backend import AsyncToken
from .._common import Call, Written, base, delay, retryable, written
from ..errors import KonklavError, from_response
from . import resources
from .auth import Auth, resolve
from .batch import Batch
from .resources import Direct

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

    The operations are grouped as the API document tags them, such as
    `client.tenants.create(...)` and `client.roles.put(...)`. `batch()`
    collects writes made through the same namespaces and applies them in
    one request, all or nothing.
    """

    tenants: resources.Tenants[Direct]
    memberships: resources.Memberships[Direct]
    subjects: resources.Subjects[Direct]
    credentials: resources.Credentials[Direct]
    sessions: resources.Sessions[Direct]
    signing_keys: resources.SigningKeys[Direct]
    catalog: resources.Catalog[Direct]
    templates: resources.Templates[Direct]
    roles: resources.Roles[Direct]
    assignments: resources.Assignments[Direct]
    entitlements: resources.Entitlements[Direct]
    explain: resources.Explain[Direct]
    shares: resources.Shares[Direct]
    registered_scopes: resources.RegisteredScopes[Direct]
    invites: resources.Invites[Direct]
    oidc_clients: resources.OidcClients[Direct]
    imports: resources.Imports[Direct]
    batches: resources.Batches[Direct]

    # r[impl item.py-control-plane.injectable-http]
    # r[impl item.py-control-plane.explicit-config]
    def __init__(
        self,
        url: str,
        *,
        auth: Auth | Callable[[], AsyncToken],
        http: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        if retries < 0:
            raise ValueError("retries can't be negative")
        self._url = f"{base(url)}/v1"
        self._auth = resolve(auth)
        self._owns_http = http is None
        # The environment holds no configuration for this client.
        self._http = http if http is not None else httpx.AsyncClient(timeout=timeout, trust_env=False)
        self._retries = retries
        self.tenants = resources.Tenants(self)
        self.memberships = resources.Memberships(self)
        self.subjects = resources.Subjects(self)
        self.credentials = resources.Credentials(self)
        self.sessions = resources.Sessions(self)
        self.signing_keys = resources.SigningKeys(self)
        self.catalog = resources.Catalog(self)
        self.templates = resources.Templates(self)
        self.roles = resources.Roles(self)
        self.assignments = resources.Assignments(self)
        self.entitlements = resources.Entitlements(self)
        self.explain = resources.Explain(self)
        self.shares = resources.Shares(self)
        self.registered_scopes = resources.RegisteredScopes(self)
        self.invites = resources.Invites(self)
        self.oidc_clients = resources.OidcClients(self)
        self.imports = resources.Imports(self)
        self.batches = resources.Batches(self)

    def batch(self, *, idempotency_key: str | None = None, idempotency_seconds: int | None = None) -> Batch:
        """A batch: `async with client.batch() as batch:` collects the writes
        made through `batch`'s namespaces, which mirror the client's, and
        sends them in one request on leaving the block without an error.

        With an `idempotency_key`, sending the same batch again answers what
        it first answered without applying it again, so it is retried like a
        `PUT`. The server remembers the key for `idempotency_seconds`, or its
        default (ten minutes) when `None`.
        """
        return Batch(self, idempotency_key=idempotency_key, idempotency_seconds=idempotency_seconds)

    async def __aenter__(self) -> ControlPlaneClient:
        return self

    async def __aexit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Closes the `httpx` client, unless it was passed in."""
        if self._owns_http:
            await self._http.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Sends a request to `path` under `/v1` and returns its decoded
        JSON body, or `None` when it has none."""
        response = await self._send(method, f"{self._url}{path}", json=json, params=params)
        return response.json() if response.content else None

    async def _get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        """A `GET`, leaving out query parameters that are `None`."""
        query = {name: value for name, value in (params or {}).items() if value is not None}
        return await self.request("GET", path, params=query)

    async def _post(self, path: str, body: Any = None) -> Any:
        return await self.request("POST", path, json=body)

    async def _write(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        create: bool = False,
    ) -> Written[Any]:
        """Sends a write and splits the cursor off its result."""
        response = await self._send(method, f"{self._url}{path}", json=json, params=params)
        return written(response.status_code, response.json(), create=create)

    async def _call(self, call: Call) -> Any:
        """Sends `call` and returns what its method returns."""
        response = await self._send(call.method, f"{self._url}{call.path}", json=call.json, params=call.query())
        return call.result(response.status_code, response.json() if response.content else None)

    # r[impl item.py-control-plane.paging]
    async def _pages(
        self, path: str, key: str, params: Mapping[str, Any] | None = None
    ) -> AsyncIterator[Any]:
        """Every item of a paged list, page after page."""
        query = {name: value for name, value in (params or {}).items() if value is not None}
        while True:
            page = await self._get(path, query)
            for item in page[key]:
                yield item
            if page.get("next") is None:
                return
            query["before"] = page["next"]

    async def _send(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        authenticate: bool = True,
        retry_as: str | None = None,
    ) -> httpx.Response:
        """Sends a request, logging in again once and retrying as allowed,
        as for `retry_as` when given instead of `method`."""
        attempt = 0
        relogged = False
        while True:
            headers = {}
            if authenticate:
                headers["authorization"] = f"Bearer {await self._auth.token(self)}"
            cause: Exception | None = None
            try:
                response = await self._http.request(
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
            if attempt >= self._retries or not retryable(retry_as or method, failure):
                raise failure from cause
            await _backend.async_sleep(delay(attempt, failure))
            attempt += 1
