"""Pacing and fake ids. Timing tests assert lower bounds only, so a loaded machine can't fail them."""

import ast
import asyncio
import doctest
import pathlib
import time
import uuid
from collections.abc import Coroutine
from datetime import timedelta
from typing import Any

import pytest

import konklav_relying
from konklav_relying import Pacing, fake_uuid7, paced
from konklav_relying import fake_ids as fake_ids_module
from konklav_relying import pacing as pacing_module
from konklav_relying.fake_ids import claimed_ms

PACKAGE = pathlib.Path(konklav_relying.__file__).parent
FLOOR = timedelta(milliseconds=100)
PACING = Pacing(floor=FLOOR)
# Below the floor, for scheduling slack in the lower bounds.
AT_LEAST = 0.095


@pytest.mark.parametrize("module", [pacing_module, fake_ids_module], ids=lambda m: m.__name__)
def test_doctests(module: object) -> None:
    failed, tried = doctest.testmod(module, optionflags=doctest.ELLIPSIS)
    assert tried > 0 and failed == 0


# r[verify item.py.pacing.framework-free]
def test_pacing_and_fake_ids_import_only_the_standard_library() -> None:
    allowed = {"__future__", "asyncio", "collections", "contextlib", "dataclasses", "datetime", "secrets", "time", "typing", "uuid"}
    for name in ("pacing.py", "fake_ids.py"):
        for node in ast.walk(ast.parse((PACKAGE / name).read_text())):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] in allowed, node.module
            elif isinstance(node, ast.Import):
                assert all(alias.name.split(".")[0] in allowed for alias in node.names), name


def elapsed(work: Coroutine[Any, Any, object]) -> float:
    async def run() -> float:
        start = time.monotonic()
        try:
            await work
        except ValueError:
            pass
        return time.monotonic() - start

    return asyncio.run(run())


# r[verify item.py.pacing.delay]
def test_delays_stay_within_the_jitter_of_the_floor() -> None:
    pacing = Pacing(floor=timedelta(milliseconds=100), jitter=timedelta(milliseconds=20))
    delays = [pacing.delay() for _ in range(1000)]
    assert all(timedelta(milliseconds=80) <= d <= timedelta(milliseconds=120) for d in delays)
    assert any(d < timedelta(milliseconds=95) for d in delays)
    assert any(d > timedelta(milliseconds=105) for d in delays)
    # Not whole milliseconds, let alone seconds.
    assert any(d.microseconds % 1000 for d in delays)


# r[verify item.py.pacing.delay]
def test_delays_never_go_below_zero_and_none_waits_not_at_all() -> None:
    wide = Pacing(floor=timedelta(milliseconds=1), jitter=timedelta(milliseconds=10))
    assert all(wide.delay() >= timedelta(0) for _ in range(200))
    assert Pacing.NONE.delay() == timedelta(0)
    assert Pacing(floor=FLOOR).delay() == FLOOR
    with pytest.raises(ValueError):
        Pacing(floor=timedelta(seconds=-1))
    with pytest.raises(ValueError):
        Pacing(floor=FLOOR, jitter=timedelta(seconds=-1))


# r[verify item.py.pacing.concurrent]
def test_paced_work_takes_at_least_the_floor_as_a_decorator_and_a_context_manager() -> None:
    @paced(PACING)
    async def decorated() -> str:
        return "done"

    async def managed() -> None:
        async with paced(PACING):
            pass

    assert elapsed(decorated()) >= AT_LEAST
    # A decorated function draws its wait anew on every call.
    assert elapsed(decorated()) >= AT_LEAST
    assert elapsed(managed()) >= AT_LEAST
    assert asyncio.run(decorated()) == "done"


# r[verify item.py.pacing.concurrent]
def test_the_work_and_the_wait_run_together() -> None:
    async def slow() -> None:
        async with paced(Pacing(floor=timedelta(milliseconds=300))):
            await asyncio.sleep(0.3)

    # 0.3 s of work and a 0.3 s floor take 0.3 s, not 0.6 s. The upper
    # bound is generous, since a loaded machine may run late.
    taken = elapsed(slow())
    assert 0.29 <= taken < 0.55


# r[verify item.py.pacing.errors]
def test_errors_propagate_only_after_the_wait() -> None:
    @paced(PACING)
    async def failing() -> None:
        raise ValueError("unknown address")

    assert elapsed(failing()) >= AT_LEAST

    async def raised() -> None:
        with pytest.raises(ValueError, match="unknown address"):
            await failing()

    asyncio.run(raised())


# r[verify item.py.pacing.cancellation]
def test_cancellation_propagates_without_the_wait() -> None:
    long = Pacing(floor=timedelta(seconds=30))

    async def scenario() -> float:
        async def work() -> None:
            async with paced(long):
                await asyncio.sleep(30)

        task = asyncio.create_task(work())
        await asyncio.sleep(0.01)
        start = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return time.monotonic() - start

    assert asyncio.run(scenario()) < 5


# r[verify item.py.pacing.cancellation]
def test_cancellation_ends_the_wait() -> None:
    long = Pacing(floor=timedelta(seconds=30))

    async def scenario() -> float:
        async def work() -> None:
            async with paced(long):
                pass

        task = asyncio.create_task(work())
        await asyncio.sleep(0.01)
        start = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return time.monotonic() - start

    assert asyncio.run(scenario()) < 5


def test_none_does_not_wait() -> None:
    async def scenario() -> None:
        async with paced(Pacing.NONE):
            pass

    assert elapsed(scenario()) < 5


# r[verify item.py.fake-id.layout]
def test_fake_ids_are_uuid7s_with_random_bits_after_the_timestamp() -> None:
    ids = [fake_uuid7() for _ in range(500)]
    assert all(i.version == 7 and i.variant == uuid.RFC_4122 for i in ids)
    assert len(set(ids)) == len(ids)
    rand_a = {i.int >> 64 & 0xFFF for i in ids}
    rand_b = [i.int & (1 << 62) - 1 for i in ids]
    # Every one of the 74 bits after the timestamp is set in some id.
    assert max(rand_a).bit_length() == 12 and len(rand_a) > 400
    assert max(rand_b).bit_length() == 62
    random_bits = 0xFFF << 64 | (1 << 62) - 1
    combined = 0
    for i in ids:
        combined |= i.int & random_bits
    assert combined == random_bits


# r[verify item.py.fake-id.time]
def test_fake_ids_claim_now_by_default() -> None:
    before = time.time_ns() // 1_000_000
    fake = fake_uuid7()
    after = time.time_ns() // 1_000_000
    assert before <= claimed_ms(fake) <= after


# r[verify item.py.fake-id.time]
def test_fake_ids_claim_a_random_millisecond_within_the_window() -> None:
    window = timedelta(days=365)
    before = time.time_ns() // 1_000_000
    claimed = [claimed_ms(fake_uuid7(within=window)) for _ in range(1000)]
    after = time.time_ns() // 1_000_000
    span = window // timedelta(milliseconds=1)
    assert all(before - span <= at <= after for at in claimed)
    # Spread over the whole year, not the first 264 days of it.
    assert min(claimed) < before - span * 0.95
    assert max(claimed) > before - span * 0.05
    # Not whole seconds.
    assert any(at % 1000 for at in claimed)
    for empty in (timedelta(0), timedelta(days=-1)):
        with pytest.raises(ValueError):
            fake_uuid7(within=empty)


def test_claimed_ms_reads_only_uuid7s() -> None:
    with pytest.raises(ValueError):
        claimed_ms(uuid.uuid4())
