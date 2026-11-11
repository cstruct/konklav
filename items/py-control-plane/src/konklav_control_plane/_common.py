"""What the async and sync clients share: no I/O happens here."""

from __future__ import annotations

import json
import random
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Generic, TypeVar, cast
from urllib.parse import quote, urlencode

import httpx

from .errors import KonklavError, RateLimited

T = TypeVar("T")
F = TypeVar("F", bound=Callable[..., Any])

# Idempotent on the control-plane surface, so a request that may or may not
# have taken effect can be sent again.
IDEMPOTENT = frozenset({"GET", "PUT", "DELETE"})

# Retried only for idempotent methods: the server may have acted first.
_UNSAFE_CODES = frozenset({"OVERLOADED", "DATABASE_UNAVAILABLE", "MIGRATIONS_PENDING"})

BACKOFF_BASE = 0.5
BACKOFF_CAP = 10.0


@dataclass(frozen=True)
class Written(Generic[T]):
    """A write's result.

    `value` is the resource. `cursor` is the change-feed cursor of the last
    event the write produced, or `None` when it produced none; pass it to
    `konklav_relying.RelyingClient.await_cursor` for read-your-writes.
    `created` is set for idempotent creates: `True` when the server created
    the resource, `False` when it already existed with the same content.
    """

    value: T
    cursor: int | None = None
    created: bool | None = None


# r[impl item.py-control-plane.write-cursor]
# r[impl item.py-control-plane.created]
def written(status: int, body: Any, *, create: bool = False) -> Written[Any]:
    """Splits a write's `cursor` off its body."""
    cursor = body.pop("cursor", None) if isinstance(body, dict) else None
    created = status == httpx.codes.CREATED if create else None
    return Written(value=body, cursor=cursor, created=created)


class Mode(StrEnum):
    """Whether a namespace sends its calls (`DIRECT`, the client's) or
    collects writes into a batch (`BATCH`)."""

    DIRECT = "direct"
    BATCH = "batch"


@dataclass(frozen=True)
class Call:
    """One operation as a client method describes it, to send now or in a
    batch, and how to turn its answer into what the method returns."""

    method: str
    path: str
    json: Any = None
    params: Mapping[str, Any] | None = None
    create: bool = False
    written: bool = False
    if_match: str | None = None

    def query(self) -> dict[str, Any]:
        return {name: value for name, value in (self.params or {}).items() if value is not None}

    def headers(self) -> dict[str, str]:
        """The call's own headers: `If-Match` when it has a precondition."""
        return {"if-match": f'"{self.if_match}"'} if self.if_match is not None else {}

    def operation(self) -> dict[str, Any]:
        """The call as an operation of a batch."""
        query = urlencode(self.query())
        operation: dict[str, Any] = {"method": self.method, "path": f"{self.path}?{query}" if query else self.path}
        if self.json is not None:
            operation["body"] = self.json
        if self.if_match is not None:
            operation["if_match"] = self.if_match
        return operation

    def result(self, status: int, body: Any) -> Any:
        """What the method returns for an answer with `status` and `body`."""
        return written(status, body, create=self.create) if self.written else body


class Pending(Generic[T]):
    """What a method called on a batch's namespace returns: its `result` is
    what the method returns on the client, once the batch has been sent."""

    def __init__(self) -> None:
        self._sent = False
        self._result: Any = None

    @property
    def result(self) -> T:
        if not self._sent:
            raise RuntimeError("the batch hasn't been sent")
        return cast(T, self._result)

    def _resolve(self, result: Any) -> None:
        self._result = result
        self._sent = True

    def __repr__(self) -> str:
        return f"Pending({self._result!r})" if self._sent else "Pending(<not sent>)"


# r[impl item.py-control-plane.retries]
# r[impl item.py-control-plane.no-ambiguous-retry]
def retryable(method: str, error: KonklavError) -> bool:
    """Whether a request that failed with `error` may be sent again.
    `method` is the request's, or `PUT` for a batch with an idempotency key,
    which a repeat can't apply twice."""
    if error.code == "RATE_LIMITED":
        return True
    if method not in IDEMPOTENT:
        return False
    # No response: a connection error or timeout.
    return error.status is None or error.code in _UNSAFE_CODES


def delay(attempt: int, error: KonklavError) -> float:
    """Seconds to wait before retry `attempt` (from 0)."""
    if isinstance(error, RateLimited) and error.retry_after is not None:
        return error.retry_after
    # Full jitter, so clients that failed together don't retry together.
    return random.uniform(0, min(BACKOFF_CAP, BACKOFF_BASE * 2**attempt))


# r[impl item.py-control-plane.base-url]
def base(url: str) -> str:
    """The surface's URL with any proxy prefix and without a trailing `/`."""
    return url.rstrip("/")


# r[impl item.py-control-plane.whole-surface]
def operation(operation_id: str) -> Callable[[F], F]:
    """Marks a method as the client's for the API document's operation
    `operation_id`, which the tests check every operation has."""

    def mark(method: F) -> F:
        setattr(method, "__konklav_operation__", operation_id)
        return method

    return mark


MetadataFilter = Mapping[str, str | int | float | bool]
"""A list's metadata filter: only objects whose metadata has each key at its
top level with an equal value."""


# r[impl metadata.filter]
def metadata_filter(metadata: MetadataFilter | None) -> str | None:
    """A metadata filter as the `metadata` query parameter: a JSON object."""
    return None if metadata is None else json.dumps(dict(metadata), separators=(",", ":"), sort_keys=True)


def path(*segments: str) -> str:
    """A path under `/v1` from literal segments and caller-given ids, which
    are escaped so they stay one segment each."""
    return "".join(f"/{quote(segment, safe='')}" for segment in segments)
