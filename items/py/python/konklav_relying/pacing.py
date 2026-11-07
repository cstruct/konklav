"""
Pacing: answer no sooner than a floor plus or minus a random jitter.

An endpoint whose answer could reveal whether a record exists, such as
inviting an address or starting a password reset, often does more work for
a known record than for an unknown one. Paced, it runs its work and a wait
drawn from `floor ± jitter` together, and answers when both are done, so
its response time is the floor (plus jitter) unless the work takes longer.
Konklav paces its own authentication endpoints the same way.

`paced` is both an async context manager and a decorator:

>>> import asyncio
>>> from datetime import timedelta
>>> pacing = Pacing(floor=timedelta(milliseconds=20), jitter=timedelta(milliseconds=5))
>>> @paced(pacing)
... async def invite(address: str) -> str:
...     return "sent"
>>> asyncio.run(invite("someone@example.com"))
'sent'

```python
async with paced(pacing):
    await maybe_send_invite(address)
```

The wait also runs when the work raises, so a failure answers no sooner
than a success. Cancellation is not paced: it propagates at once, since
whoever cancelled (a client that went away, a timeout, a shutdown) isn't
waiting for the answer. In tests, use `Pacing.NONE`.

The wait is an `asyncio` sleep, measured on the event loop's monotonic
clock from when the work starts.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import ClassVar

__all__ = ["Pacing", "paced"]

_MICROSECOND = timedelta(microseconds=1)


# r[impl item.py.pacing.framework-free]
@dataclass(frozen=True)
class Pacing:
    """
    How long a paced endpoint takes at least: `floor ± jitter`.

    >>> Pacing(floor=timedelta(seconds=1), jitter=timedelta(seconds=2)).delay() >= timedelta(0)
    True
    >>> Pacing.NONE.delay()
    datetime.timedelta(0)
    """

    floor: timedelta
    jitter: timedelta = timedelta(0)

    NONE: ClassVar[Pacing]
    """No wait at all, for tests."""

    def __post_init__(self) -> None:
        if self.floor < timedelta(0) or self.jitter < timedelta(0):
            raise ValueError("a pacing's floor and jitter can't be negative")

    # r[impl item.py.pacing.delay]
    def delay(self) -> timedelta:
        """A wait drawn uniformly from `floor ± jitter`, and never below zero."""
        span = self.jitter // _MICROSECOND * 2
        if span == 0:
            return self.floor
        offset = timedelta(microseconds=secrets.randbelow(span + 1))
        return max(self.floor - self.jitter + offset, timedelta(0))


Pacing.NONE = Pacing(floor=timedelta(0))


async def _wait_until(deadline: float) -> None:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining > 0:
        await asyncio.sleep(remaining)


# r[impl item.py.pacing.concurrent]
@asynccontextmanager
async def paced(pacing: Pacing) -> AsyncIterator[None]:
    """
    Runs the work inside (or the decorated function) and a wait drawn from
    `pacing`, and finishes when both are done, also when the work raises.
    Cancellation propagates at once, without waiting.
    """
    deadline = asyncio.get_running_loop().time() + pacing.delay().total_seconds()
    try:
        yield
    # r[impl item.py.pacing.errors]
    except Exception:
        await _wait_until(deadline)
        raise
    # r[impl item.py.pacing.cancellation]
    # Anything else, `CancelledError` and `KeyboardInterrupt` among them,
    # isn't an answer: it propagates without a wait.
    await _wait_until(deadline)
