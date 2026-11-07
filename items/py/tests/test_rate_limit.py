"""
Rate limits in memory, and against a real Redis when `KONKLAV_TEST_REDIS_URL`
or `REDIS_URL` is set (mise sets it; `mise run db:up` starts Redis).
"""

import asyncio
import os
import time
import uuid
from datetime import timedelta

import pytest
import redis.asyncio
from konklav_relying import RateLimit, RateLimited, RateLimitWindow

SECRET = b"0123456789abcdef0123456789abcdef"
REDIS_URL = os.environ.get("KONKLAV_TEST_REDIS_URL") or os.environ.get("REDIS_URL")
needs_redis = pytest.mark.skipif(not REDIS_URL, reason="no test Redis (set KONKLAV_TEST_REDIS_URL or REDIS_URL)")


def window(size: int, ms: int) -> RateLimitWindow:
    return RateLimitWindow(size=size, period=timedelta(milliseconds=ms))


def unique_name() -> str:
    return f"test-{uuid.uuid4().hex}"


async def admitted(limit: RateLimit, key: str | bytes) -> bool:
    try:
        await limit.add(key)
    except RateLimited:
        return False
    return True


# r[verify item.py.rate-limit.add]
# r[verify relying.rate-limit.windows]
# r[verify relying.rate-limit.retry-after]
def test_add_admits_a_burst_then_raises_with_the_wait() -> None:
    async def scenario() -> None:
        limit = RateLimit("login", [window(2, 1000), window(3, 60_000)])
        await limit.add("a@example.com")
        await limit.add(b"a@example.com")
        with pytest.raises(RateLimited) as refused:
            await limit.add("a@example.com")
        assert timedelta(milliseconds=1) <= refused.value.retry_after <= timedelta(milliseconds=500)
        # Other keys are limited separately.
        await limit.add("b@example.com")
        limit.clear()
        await limit.add("a@example.com")

    asyncio.run(scenario())


# r[verify relying.rate-limit.local-divisor]
def test_the_local_divisor_divides_window_sizes() -> None:
    async def scenario() -> None:
        limit = RateLimit("login", [window(9, 60_000)], local_divisor=3)
        assert [await admitted(limit, "k") for _ in range(4)] == [True, True, True, False]

    asyncio.run(scenario())


def test_invalid_limits_are_refused() -> None:
    with pytest.raises(ValueError, match="name"):
        RateLimit("Login", [window(1, 1000)])
    with pytest.raises(ValueError, match="window"):
        RateLimit("login", [])
    with pytest.raises(ValueError, match="millisecond"):
        RateLimit("login", [RateLimitWindow(size=1, period=timedelta(microseconds=10))])
    unused = redis.asyncio.Redis()
    # r[verify relying.rate-limit.key-privacy]
    with pytest.raises(ValueError, match="secret"):
        RateLimit("login", [window(1, 1000)], redis=unused)
    with pytest.raises(ValueError, match="32 bytes"):
        RateLimit("login", [window(1, 1000)], redis=unused, secret=b"short")


def connect(url: str) -> redis.asyncio.Redis:
    return redis.asyncio.Redis.from_url(url, socket_connect_timeout=0.2, socket_timeout=0.2)


def stored(url: str, name: str, windows: list[RateLimitWindow]) -> RateLimit:
    return RateLimit(name, windows, redis=connect(url), secret=SECRET)


# r[verify item.py.rate-limit.redis]
# r[verify relying.rate-limit.shared]
@needs_redis
def test_limits_sharing_a_store_enforce_one_limit() -> None:
    assert REDIS_URL
    url = REDIS_URL

    async def scenario() -> None:
        name = unique_name()
        a = stored(url, name, [window(3, 60_000)])
        b = stored(url, name, [window(3, 60_000)])
        assert [await admitted(limit, "k") for limit in (a, b, a, b)] == [True, True, True, False]
        with pytest.raises(RateLimited) as refused:
            await a.add("k")
        assert timedelta(seconds=19) <= refused.value.retry_after <= timedelta(seconds=20)

    asyncio.run(scenario())


# r[verify relying.rate-limit.key-privacy]
# r[verify relying.rate-limit.expiry]
@needs_redis
def test_store_keys_are_hashed_and_expire() -> None:
    assert REDIS_URL
    url = REDIS_URL

    async def scenario() -> None:
        name = unique_name()
        limit = stored(url, name, [window(1, 300)])
        await limit.add("a@example.com")
        client = connect(url)
        keys = await client.keys(f"konklav:rl:{{{name}:*")
        assert len(keys) == 1
        assert b"example" not in keys[0]
        await asyncio.sleep(0.4)
        assert await client.keys(f"konklav:rl:{{{name}:*") == []

    asyncio.run(scenario())


class Proxy:
    """A TCP proxy to Redis that can be cut and restored."""

    def __init__(self, target: str) -> None:
        host, _, port = target.removeprefix("redis://").rstrip("/").rpartition(":")
        self.target = (host, int(port))
        self.up = True
        self.tasks: set[asyncio.Task[None]] = set()
        self.url = ""

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.url = "redis://127.0.0.1:{}".format(self.server.sockets[0].getsockname()[1])

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self.up:
            writer.close()
            return
        task = asyncio.current_task()
        assert task
        self.tasks.add(task)
        upstream_reader, upstream_writer = await asyncio.open_connection(*self.target)

        async def pipe(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
            while data := await source.read(65536):
                sink.write(data)
                await sink.drain()

        try:
            await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))
        finally:
            writer.close()
            upstream_writer.close()
            self.tasks.discard(task)

    def cut(self) -> None:
        self.up = False
        for task in list(self.tasks):
            task.cancel()

    def restore(self) -> None:
        self.up = True


# r[verify relying.rate-limit.fallback]
# r[verify relying.rate-limit.local]
@needs_redis
def test_a_lost_store_falls_back_to_memory_and_recovers() -> None:
    assert REDIS_URL
    url = REDIS_URL

    async def scenario() -> None:
        proxy = Proxy(url)
        await proxy.start()
        name = unique_name()
        proxied = stored(proxy.url, name, [window(2, 60_000)])
        direct = stored(url, name, [window(2, 60_000)])

        # Counted in the store and in memory.
        assert await admitted(proxied, "k")

        proxy.cut()
        started = time.monotonic()
        assert await admitted(proxied, "k"), "memory admits a second"
        assert not await admitted(proxied, "k"), "memory refuses a third"
        assert time.monotonic() - started < 0.5, "answered within the timeout"

        # The store only saw one event.
        proxy.restore()
        await asyncio.sleep(1.1)
        assert await admitted(proxied, "k"), "the store answers again after the backoff"
        assert not await admitted(direct, "k"), "and the limit is shared again"

    asyncio.run(scenario())
