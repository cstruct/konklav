"""
Fake ids: UUIDv7s to answer with in place of real ones.

An endpoint that creates something, or reports what it created, can give
away that nothing was created: an invite to an unknown address that answers
with no id, or with an id that doesn't look like the others. `fake_uuid7`
makes a UUIDv7 that only the relying system's own records can tell from a
real one.

A UUIDv7 carries the millisecond it was made, so the caller chooses the
time a fake one claims:

- `fake_uuid7()` claims now. Use it in place of something the request
  would have just created, such as the invite for an address that has no
  account: the real answer carries a fresh id, so the fake one must too.
- `fake_uuid7(within=timedelta(days=365))` claims a millisecond drawn
  uniformly from the past year. Use it in place of something that would
  already exist, such as the id of an account looked up by an address that
  has none. A fresh id there would give the lookup away.

>>> from datetime import timedelta
>>> fake = fake_uuid7()
>>> fake.version, fake.variant == uuid.RFC_4122
(7, True)
>>> claimed_ms(fake_uuid7(within=timedelta(days=30))) <= claimed_ms(fake_uuid7())
True

Everything after the timestamp is random, as RFC 9562's basic layout has
it. If the relying system's real ids fix some of those bits, such as with a
counter (Python 3.14's `uuid.uuid7` seeds one whose top bit is zero), the
fakes differ from them in those bits; make real ids the same way, or wrap
this to match.

Fake ids are worth nothing alone: the answer they're part of must be paced
too (`konklav_relying.pacing`), or how long it takes gives it away.
"""

from __future__ import annotations

import secrets
import time
import uuid
from datetime import timedelta

__all__ = ["claimed_ms", "fake_uuid7"]

_VERSION = 0x7
_VARIANT = 0b10
_MILLISECOND = timedelta(milliseconds=1)


# r[impl item.py.pacing.framework-free]
# r[impl item.py.fake-id.time]
def fake_uuid7(*, within: timedelta | None = None) -> uuid.UUID:
    """
    A UUIDv7 that claims the current millisecond or, with `within`, a
    millisecond drawn uniformly from that long ago up to now.

    >>> fake_uuid7(within=timedelta(0))
    Traceback (most recent call last):
    ...
    ValueError: a fake id's window must be positive
    """
    now_ms = time.time_ns() // 1_000_000
    if within is None:
        at_ms = now_ms
    elif within <= timedelta(0):
        raise ValueError("a fake id's window must be positive")
    else:
        at_ms = now_ms - secrets.randbelow(within // _MILLISECOND + 1)
    return _uuid7(at_ms)


# r[impl item.py.fake-id.layout]
def _uuid7(unix_ms: int) -> uuid.UUID:
    # RFC 9562, section 5.7: unix_ts_ms (48) | ver (4) | rand_a (12) | var (2) | rand_b (62).
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    value = (unix_ms & (1 << 48) - 1) << 80 | _VERSION << 76 | rand_a << 64 | _VARIANT << 62 | rand_b
    return uuid.UUID(int=value)


def claimed_ms(id: uuid.UUID) -> int:
    """
    The Unix time in milliseconds a UUIDv7 claims, real or fake.

    >>> claimed_ms(uuid.UUID("01890a5d-ac96-774b-bcce-b302099a8057"))
    1688096058518
    """
    if id.version != _VERSION:
        raise ValueError("only a UUIDv7 claims a time")
    return id.int >> 80
