# konklav-relying

Decide [Konklav](https://github.com/cstruct/konklav) authorization locally
from Python.

Konklav is a standalone identity and access service. This package is the
Python SDK for relying systems: services that accept Konklav's tokens and
need authorization decisions for them. It verifies tokens offline, caches
entitlements and keeps them fresh from Konklav's change feed, so most
decisions need no network round trip.

## Installing

```sh
pip install konklav-relying
```

Wheels are published for Python 3.12 and later on:

- Linux x86_64 and aarch64 with glibc 2.28 or later (manylinux_2_28)
- Linux x86_64 and aarch64 with musl 1.2 or later, such as Alpine
  (musllinux_1_2)
- macOS on Apple silicon

Elsewhere pip builds from the sdist, which needs a Rust toolchain.

## Usage

```python
from konklav_relying import RelyingClient

client = RelyingClient(
    relying_url="https://konklav:8081",
    subject_url="https://konklav:8080",
    key_id=key_id,
    secret=secret,
    issuer="https://auth.example",
    audiences={"api", "app"},
)
await client.start()

decision = await client.decide(
    token,
    {"scopes": [{"kind": "project", "id": project_id, "actions": ["document:read"]}]},
)
if decision["decision"] != "allow":
    ...

await client.stop()
```

`RelyingClient` runs on asyncio with httpx:

- It logs in as a service principal and follows the change feed in the
  background, so revocations and entitlement changes take effect within
  about a second.
- It decides locally, and falls back to Konklav's check API whenever its
  caches can't be trusted, for example while the feed is disconnected.
- `KonklavError` means Konklav could not be reached or answered with an
  error. Treat it as a deny.
- `await_cursor` waits until a change you just made through Konklav has
  reached the cache, for read-your-writes.
- `decide_request` and `verify_request` take a request's raw
  `Authorization` and `DPoP` headers, its method and the public URL, so
  sender-constrained (DPoP) tokens work too. A deny with reason
  `invalid_dpop_proof` should be answered with 401 and
  `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
- `accept_request` verifies a request's token, session and DPoP proof
  once and returns the verified token, and `decide_accepted` then decides
  for it without spending the proof again, as often as the request needs,
  for hosts that need the token before they know the requirements or that
  decide more than once; `release_accepted` ends it once the request is
  answered.

- `Policy` declares an operation's requirements once per route or router,
  merges the policies of nested layers and resolves them per request with
  the scope ids it names. `decide_typed`, `decide_request_typed`,
  `verify_typed` and `verify_request_typed` return a `Decision` and an
  `AccessToken` instead of JSON:

  ```python
  policy = Policy(tenant_actions={"project:read"}, tenant_facts={"tenant_type": ["client"]})
  decision = await client.decide_typed(token, policy.requirements())
  if not decision.allowed:
      ...
  ```

For a relying system's own endpoints that could reveal whether a record
exists, such as inviting an address or starting a password reset:

- `paced(Pacing(floor, jitter))`, an async context manager and decorator,
  answers no sooner than `floor ± jitter` (drawn from `secrets`), also when
  the work raises. Cancellation isn't paced. Tests use `Pacing.NONE`.
- `fake_uuid7()` makes a UUIDv7 to answer with in place of one that wasn't
  created, claiming now; `fake_uuid7(within=timedelta(days=365))` claims a
  random time in the past year, for records that would already exist.

```python
from datetime import timedelta

from konklav_relying import Pacing, fake_uuid7, paced

pacing = Pacing(floor=timedelta(milliseconds=800), jitter=timedelta(milliseconds=200))

async def invite(address: str) -> str:
    async with paced(pacing):
        member = await find_member(address)
        return str(await send_invite(member) if member else fake_uuid7())
```

The decision logic lives in a Rust core shared with Konklav's other relying
bindings, so they can't disagree. Python does only the I/O.

## Rate limits

`RateLimit` bounds how often events may happen per key, over several
windows. With the `redis` extra (`pip install konklav-relying[redis]`),
every process sharing a Valkey or Redis server enforces one limit
together, and falls back to counting in memory while it is unavailable:

```python
login = RateLimit(
    "login",
    [RateLimitWindow(size=5, period=timedelta(minutes=1))],
    redis=redis.asyncio.Redis.from_url(redis_url),
    secret=rate_limit_secret,
)
try:
    await login.add(email)
except RateLimited as limited:
    ...  # retry after limited.retry_after
```

## Versions

The package has the same version as the Konklav server it was released
with. Pre-releases, such as `1.3.0rc1`, are installed only with
`pip install --pre`.

## Links

- [Konklav](https://github.com/cstruct/konklav)
- [This binding's README](https://github.com/cstruct/konklav/tree/main/items/py)
- [Relying SDK design](https://github.com/cstruct/konklav/blob/main/docs/architecture/relying-sdk.md)
- [Releases and changelog](https://github.com/cstruct/konklav/releases)
- [Issues](https://github.com/cstruct/konklav/issues)

MIT licensed.
