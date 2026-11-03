"""The concurrency primitives each client uses, under the names that
`unasync` maps from the async source to the sync one."""

import asyncio
import threading
import time
from collections.abc import Awaitable

AsyncLock = asyncio.Lock
SyncLock = threading.Lock


async def async_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def sync_sleep(seconds: float) -> None:
    time.sleep(seconds)


def now() -> float:
    return time.monotonic()


# What a token callable returns: the async client also awaits it.
type AsyncToken = str | Awaitable[str]
type SyncToken = str
