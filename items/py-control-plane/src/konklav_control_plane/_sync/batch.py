# Generated from ../_async by tools/generate.py; don't edit.
"""Batches: writes collected through the client's namespaces and applied in
one request, all or nothing."""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING, Any

from .._common import Call, Pending
from . import resources
from .resources import Batched

if TYPE_CHECKING:
    from .client import ControlPlaneClient


# r[impl item.py-control-plane.batch]
class Batch:
    """Writes to apply in one request, all or nothing; make one with
    `client.batch()`.

    Its namespaces mirror the client's, writes only. Each call is recorded
    and returns a `Pending`, whose `result` is what the same call on the
    client returns, once the batch has been sent: on leaving `async with`
    without an error, or by `send()`. Later operations name what earlier ones
    create by the ids the caller chose for them. If an operation fails,
    nothing is applied and its error is raised, with its position as
    `operation`. `cursor` is then the change-feed cursor of the last event
    the batch produced, if any.
    """

    tenants: resources.Tenants[Batched]
    memberships: resources.Memberships[Batched]
    subjects: resources.Subjects[Batched]
    credentials: resources.Credentials[Batched]
    sessions: resources.Sessions[Batched]
    signing_keys: resources.SigningKeys[Batched]
    catalog: resources.Catalog[Batched]
    templates: resources.Templates[Batched]
    roles: resources.Roles[Batched]
    assignments: resources.Assignments[Batched]
    shares: resources.Shares[Batched]
    registered_scopes: resources.RegisteredScopes[Batched]
    invites: resources.Invites[Batched]
    oidc_clients: resources.OidcClients[Batched]
    imports: resources.Imports[Batched]

    def __init__(
        self,
        client: ControlPlaneClient,
        *,
        idempotency_key: str | None = None,
        idempotency_seconds: int | None = None,
    ) -> None:
        self._client = client
        self._key = idempotency_key
        self._seconds = idempotency_seconds
        self._calls: list[tuple[Call, Pending[Any]]] = []
        self._sent = False
        self.cursor: int | None = None
        self.tenants = resources.Tenants(client, self)
        self.memberships = resources.Memberships(client, self)
        self.subjects = resources.Subjects(client, self)
        self.credentials = resources.Credentials(client, self)
        self.sessions = resources.Sessions(client, self)
        self.signing_keys = resources.SigningKeys(client, self)
        self.catalog = resources.Catalog(client, self)
        self.templates = resources.Templates(client, self)
        self.roles = resources.Roles(client, self)
        self.assignments = resources.Assignments(client, self)
        self.shares = resources.Shares(client, self)
        self.registered_scopes = resources.RegisteredScopes(client, self)
        self.invites = resources.Invites(client, self)
        self.oidc_clients = resources.OidcClients(client, self)
        self.imports = resources.Imports(client, self)

    def _add(self, call: Call) -> Pending[Any]:
        if self._sent:
            raise RuntimeError("the batch was sent already")
        pending: Pending[Any] = Pending()
        self._calls.append((call, pending))
        return pending

    def send(self) -> None:
        """Sends the recorded writes. A batch is sent once; one with nothing
        recorded sends nothing."""
        if self._sent:
            raise RuntimeError("the batch was sent already")
        self._sent = True
        if not self._calls:
            return
        body: dict[str, Any] = {"operations": [call.operation() for call, _ in self._calls]}
        if self._key is not None:
            body["idempotency_key"] = self._key
        if self._seconds is not None:
            body["idempotency_seconds"] = self._seconds
        response = self._client._send(
            "POST",
            f"{self._client._url}/batch",
            json=body,
            # r[impl item.py-control-plane.retries]
            retry_as="PUT" if self._key is not None else None,
        )
        answer = response.json()
        self.cursor = answer.get("cursor")
        for (call, pending), result in zip(self._calls, answer["results"], strict=True):
            pending._resolve(call.result(result["status"], result["body"]))

    def __enter__(self) -> Batch:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if error is None:
            self.send()
