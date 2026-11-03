"""What the async and sync clients share: no I/O happens here."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

import httpx

from .errors import KonklavError, RateLimited

T = TypeVar("T")

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
def written(response: httpx.Response, *, create: bool = False) -> Written[Any]:
    """Splits a write's `cursor` off its body."""
    body = response.json()
    cursor = body.pop("cursor", None) if isinstance(body, dict) else None
    created = response.status_code == httpx.codes.CREATED if create else None
    return Written(value=body, cursor=cursor, created=created)


# r[impl item.py-control-plane.retries]
# r[impl item.py-control-plane.no-ambiguous-retry]
def retryable(method: str, error: KonklavError) -> bool:
    """Whether a request that failed with `error` may be sent again."""
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
