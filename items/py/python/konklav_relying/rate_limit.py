"""
Rate limits: named bounds on how often events may happen per key.

A `RateLimit` has one or more `RateLimitWindow`s, and `add(key)` admits an
event only when every window admits it, raising `RateLimited` otherwise.
Each window lets its `size` events through at once, and after that one more
each time `period / size` has passed.

With a Redis rate-limit store (the `redis` extra), every process sharing it
enforces one limit together. Every process also tracks its limits in
memory, and answers from that state while Redis fails or is slow; a
`local_divisor` of the number of processes keeps them together near the
limit while they do.

```python
from datetime import timedelta

import redis.asyncio
from konklav_relying import RateLimit, RateLimited, RateLimitWindow

login = RateLimit(
    "login",
    [
        RateLimitWindow(size=5, period=timedelta(minutes=1)),
        RateLimitWindow(size=20, period=timedelta(hours=1)),
    ],
    redis=redis.asyncio.Redis.from_url(redis_url),
    secret=rate_limit_secret,  # at least 32 bytes, shared by every process
    local_divisor=replicas,
)

try:
    await login.add(email)
except RateLimited as limited:
    ...  # retry after limited.retry_after
```

The rules are the relying core's (`konklav_relying._core.RateLimiterCore`);
this module only runs the store's script and reports what happened.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from konklav_relying._core import STORE_SCRIPT, RateLimiterCore

if TYPE_CHECKING:
    import redis.asyncio

__all__ = ["RateLimit", "RateLimitWindow", "RateLimited"]

_log = logging.getLogger(__name__)

_MS = timedelta(milliseconds=1)


@dataclass(frozen=True)
class RateLimitWindow:
    """`size` events at once, and after that one more each `period / size`."""

    size: int
    period: timedelta


class RateLimited(Exception):
    """A refused event: its key would be admitted after `retry_after`."""

    retry_after: timedelta

    def __init__(self, retry_after: timedelta) -> None:
        super().__init__(f"rate limited; retry after {retry_after.total_seconds():.3f} s")
        self.retry_after = retry_after


def _now() -> int:
    return time.time_ns() // 1_000_000


def _refused(retry_after_ms: int | None) -> None:
    if retry_after_ms is not None:
        raise RateLimited(timedelta(milliseconds=retry_after_ms))


# r[impl item.py.rate-limit.add]
# r[impl item.py.rate-limit.redis]
class RateLimit:
    """
    A rate limit, through `redis` when given and in memory always.

    `name` identifies the limit's state in the store: limits with the same
    name and windows share it. Keys are hashed under `secret` before they
    reach the store, so every process must share it. The store is given up
    on after `timeout`, and left alone for a backoff while it fails.
    """

    DEFAULT_TIMEOUT = timedelta(milliseconds=100)
    DEFAULT_MAX_LOCAL_KEYS = 100_000

    def __init__(
        self,
        name: str,
        windows: Sequence[RateLimitWindow],
        *,
        redis: redis.asyncio.Redis | None = None,
        secret: bytes | None = None,
        local_divisor: int = 1,
        max_local_keys: int = DEFAULT_MAX_LOCAL_KEYS,
        timeout: timedelta = DEFAULT_TIMEOUT,
    ) -> None:
        if redis is not None and secret is None:
            raise ValueError("a rate limit with a store needs a secret")
        if redis is None and secret is not None:
            raise ValueError("a rate-limit secret is only for a store; pass redis too")
        for window in windows:
            if window.period < _MS:
                raise ValueError("a rate-limit window's period must be at least a millisecond")
        config = {
            "name": name,
            "windows": [{"size": w.size, "period_ms": w.period // _MS} for w in windows],
            "local_divisor": local_divisor,
            "max_local_keys": max_local_keys,
        }
        self.name = name
        self.windows = tuple(windows)
        self._core = RateLimiterCore(json.dumps(config), secret)
        self._redis = redis
        self._script: Any = redis.register_script(STORE_SCRIPT) if redis is not None else None
        self._timeout = timeout.total_seconds()

    def __repr__(self) -> str:
        return f"RateLimit(name={self.name!r}, windows={list(self.windows)!r})"

    async def add(self, key: str | bytes) -> None:
        """Counts one event for `key`, or raises `RateLimited`."""
        raw = key.encode() if isinstance(key, str) else key
        local, call = self._core.begin(raw, _now())
        if call is None:
            return _refused(local)
        keys, args = call
        try:
            async with asyncio.timeout(self._timeout):
                answer = await self._script(keys=keys, args=args)
        except Exception as error:  # noqa: BLE001 - any store failure falls back to memory
            _log.warning("rate-limit store failed for %s; answering from memory: %r", self.name, error)
            self._core.on_store_failed(_now())
            return _refused(local)
        return _refused(self._core.on_store_answer(int(answer)))

    def clear(self) -> None:
        """Forgets every key's state in memory. State in the store expires on its own."""
        self._core.clear()
