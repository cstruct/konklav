# konklav-py (`konklav-relying` on PyPI)

Python bindings for the relying core, plus an asyncio/httpx host.

## Responsibilities

- `konklav_relying._core.Core`: pyo3 bindings over `konklav-relying`. Values cross as JSON strings and times as Unix ms.
- `konklav_relying.RelyingClient`: the Python I/O layer.
  - Logs in as a service principal and follows the change feed.
  - Runs background refreshes.
  - Decides locally, falling back to `/v1/check` when caches can't be trusted.
  - Offers `await_cursor` for read-your-writes.
  - Hands erasures to the relying system: `on_erasure` is awaited with `Erased` for each subject Konklav erases and with `ErasuresMissed` when some may have been missed, which includes every start; `erased_subjects(since)` reads the erased subjects from Konklav to catch up ([erasure](../../docs/architecture/erasure.md#through-the-relying-sdk)).
- `konklav_relying.policy`: route policies (`Policy`, `StepUp`), which state an operation's requirements with scope ids unresolved, merge across nested layers and resolve to the requirements JSON. Frozen dataclasses and the standard library only, so framework integrations can build on it.
- `konklav_relying.rate_limit`: `RateLimit.add(key)`, raising `RateLimited`, over `_core.RateLimiterCore`. With the `redis` extra it shares limits through a `redis.asyncio` client the application owns, and answers from memory while Redis fails or is slow.
- `konklav_relying.results`: typed results (`Decision`, `DenyReason`, `AccessToken`, and the erasure notices `Erased` and `ErasuresMissed`) read from the JSON the core and Konklav return.
- `konklav_relying.pacing` and `konklav_relying.fake_ids`: pacing (`Pacing`, `paced`) and fake ids (`fake_uuid7`), so that a relying system's own endpoints don't reveal by their timing or their ids whether a record exists. Standard library only.

No decision logic lives in Python: a route policy only builds requirements.
Pacing and fake ids are host-level timing and id generation, so they live
here rather than in the relying core.

## Installing

```sh
pip install konklav-relying
```

Wheels are published for Python 3.12 and later on x86_64 and aarch64 Linux
(manylinux_2_28 for glibc, musllinux_1_2 for musl) and aarch64 macOS.
Elsewhere pip builds from the sdist, which needs a Rust toolchain. The
package has the same version as the Konklav server it was released with.
[`PYPI.md`](PYPI.md) is its description on PyPI, which links only to
GitHub URLs since relative links don't resolve there.

## Usage

```python
client = RelyingClient(
    relying_url="https://konklav:8081",
    subject_url="https://konklav:8080",
    key_id=key_id,
    secret=secret,
    issuer="https://auth.example",
    audiences={"api", "app"},
)
await client.start()
decision = await client.decide(token, {"scopes": [{"kind": "project", "id": project_id, "actions": ["document:read"]}]})
```

`audiences` are the token audiences this relying system accepts, such as Konklav's own (`api`) and an OIDC client's (`app`); `audience="api"` is short for one. A token verifies for any of them, also through the check API, and `AccessToken.aud` says which it carried.

For sender-constrained (DPoP) tokens, `decide_request` and `verify_request` take the request's raw `Authorization` and `DPoP` headers, its method, and the public URL the client addressed (behind a proxy, not the upstream one). A deny with reason `invalid_dpop_proof`, or `InvalidDpopProof` from `verify_request`, should be answered with 401 and `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.

A request's DPoP proof is answered once, so a host that needs the verified token before it can state the requirements doesn't call `verify_request` and then `decide_request`. Instead it calls `accept_request`, which verifies the token, its session and its proof and returns an `AcceptedRequest` with the `AccessToken`, then decides with `decide_accepted` (or `decide_accepted_typed`), as often as the request needs. Each decision rechecks the session but not the proof. Once the request is answered, `release_accepted` ends the presentation, which otherwise lasts as long as its proof is fresh.

### Erasure

A relying system that keeps data about subjects passes `on_erasure`:

```python
async def on_erasure(notice: Erased | ErasuresMissed) -> None:
    if isinstance(notice, Erased):
        await delete_everything_about(notice.subject)
    else:
        for erased in await client.erased_subjects(since=await stored_watermark()):
            await delete_everything_about(erased.subject)

client = RelyingClient(..., on_erasure=on_erasure)
```

The handler is awaited one notice at a time. `Erased` may repeat. `ErasuresMissed` comes when the feed couldn't resume where the client left off, and at every start, since the client can't know what happened while it wasn't running. A handler that raises is logged and its notice isn't repeated, so keep the time erasures are handled up to in your own storage and read `erased_subjects` from there on `ErasuresMissed`. The client drops its own cached sessions and entitlement sets for the subject before calling the handler.

### Route policies

A route policy (`Policy`) states everything a decide request expresses:
global and tenant actions, actions per scope kind, token kinds, admitted
and required session flags, step-up and tenant facts. Leave a field `None`
to leave it unconstrained. Scope ids come with each request:

```python
>>> from konklav_relying import Policy, StepUp
>>> router = Policy(
...     tenant_actions={"workspace:read"},
...     token_kinds={"identity", "tenant"},
...     tenant_facts={"tenant_type": ["client", "clinic"]},
... )
>>> route = Policy(
...     scope_actions={"workspace": {"workspace:write"}},
...     token_kinds={"tenant"},
...     step_up=StepUp(min_methods=2, max_age_seconds=300),
...     tenant_facts={"tenant_type": ["client"]},
... )
>>> policy = Policy.merge(router, route)
>>> policy.requirements({"workspace": "w-1"})
{'token_kinds': ['tenant'], 'tenant': ['workspace:read'], 'scopes': [{'kind': 'workspace', 'id': 'w-1', 'actions': ['workspace:write']}], 'step_up': {'min_methods': 2, 'max_age_seconds': 300}, 'tenant_facts': {'tenant_type': ['client']}}

```

`Policy.merge` combines the policies of nested layers, outermost first:

- actions accumulate (global, tenant, and per scope kind);
- allowed sets intersect (token kinds, admitted flags, step-up's allowed methods, each tenant fact's values), and a tenant fact whose values intersect to nothing raises `PolicyError`;
- required flags and the facts constrained accumulate;
- the strictest step-up wins: the highest minimum number of methods and the smallest maximum age;
- `None` leaves a field to the other layers.

`Policy.override(...)` replaces only the fields it sets, so a route can relax
what it inherits, and `Policy.public()` admits anyone; merging a public
policy with constraints raises `PolicyError` unless an override follows it:

```python
>>> "step_up" in Policy.merge(policy, Policy.override(step_up=StepUp())).requirements({"workspace": "w-1"})
False
>>> Policy.merge(Policy.public(), Policy.override(tenant_actions={"a"})).requirements()
{'tenant': ['a']}
>>> policy.requirements({})
Traceback (most recent call last):
...
konklav_relying.policy.MissingScopeId: no id for the required scope kind `workspace`

```

Tenant actions, tenant facts and scopes without an owner tenant always mean
the token's tenant. A host that takes a tenant from the request, such as a
route's path, must deny before deciding when it isn't the token's `tid`.
For another tenant's scope, pass its owner as
`requirements(ids, scope_tenants={"workspace": owner})`: then only shares
satisfy it.

### Typed results

`decide`, `decide_request`, `verify` and `verify_request` return the decoded
JSON. `decide_typed`, `decide_request_typed`, `verify_typed` and
`verify_request_typed` take the same arguments and return a `Decision` and
an `AccessToken`:

```python
>>> from konklav_relying import AccessToken, Decision
>>> decision = Decision.from_json({"decision": "deny", "reason": {"tenant_facts": {"fact": "tenant_type"}}})
>>> decision.allowed, decision.reason.code, decision.reason.fact
(False, 'tenant_facts', 'tenant_type')
>>> token = AccessToken.from_claims({"iss": "i", "aud": "a", "sub": "s", "knd": "tenant", "sid": "x", "sv": 1,
...     "jti": "j", "iat": 0, "exp": 900, "auth_time": 0, "tid": "t"})
>>> token.tid, token.sfl
('t', ())

```

```python
decision = await client.decide_typed(token, policy.requirements({"workspace": workspace_id}))
if not decision.allowed:
    ...
```

`await_cursor` takes the cursor a control-plane write returned, such as
`konklav-control-plane`'s `Written.cursor`; see
[`examples/python/read_your_writes.py`](../../examples/python/read_your_writes.py).

### Pacing and fake ids

An endpoint that invites an address, starts a password reset or looks up an
account usually does more work for a record that exists than for one that
doesn't, and answers with something only a real record has. Konklav hides
both for its own authentication endpoints (`authn.pacing`); these helpers
do the same for a relying system's.

`Pacing(floor, jitter)` and `paced` run the work and a wait drawn uniformly
from `floor ± jitter` together, and finish when both are done, so the floor
adds no latency when the work takes longer. `paced` is an async context
manager and a decorator:

```python
>>> import asyncio
>>> from datetime import timedelta
>>> from konklav_relying import Pacing, paced
>>> pacing = Pacing(floor=timedelta(milliseconds=50), jitter=timedelta(milliseconds=10))
>>> @paced(pacing)
... async def invite(address: str) -> str:
...     return "sent"
>>> asyncio.run(invite("someone@example.com"))
'sent'

```

- The jitter is drawn from `secrets`, with microsecond resolution, and the
  wait never goes below zero. Konklav's own default is 1.5 s ± 250 ms; pick
  a floor above what the slow path takes on a loaded host.
- The wait also runs when the work raises, so a failure answers no sooner
  than a success.
- Cancellation (and any other `BaseException`) propagates at once, without
  the wait, and cancelling during the wait ends it. Whoever cancelled, such
  as a client that went away, a timeout or a shutdown, isn't waiting for an
  answer, and waiting would hold up timeouts and shutdown.
- Tests use `Pacing.NONE`, which doesn't wait, or a small explicit pacing.
  There is no global switch to speed pacing up.

`fake_uuid7` makes a UUIDv7 to answer with in place of a real one (a fake
id): a version 7, RFC 9562 variant UUID whose 74 bits after the timestamp
come from `secrets`. A UUIDv7 carries the millisecond it was made, so the
caller chooses what a fake one claims:

- `fake_uuid7()` claims now. Use it in place of something the request would
  have just created, such as answering an invite or a creation request for
  an unknown address with an id that looks like a fresh one. A past time
  would give the fake away.
- `fake_uuid7(within=timedelta(days=365))` claims a millisecond drawn
  uniformly from the past year. Use it in place of something that would
  already exist, such as the account id a lookup by address returns. Pick a
  window that matches the age of the real records.

An endpoint that creates a link-only invite (one without an address, whose
token Konklav shows once for you to share) needs neither: no address is
looked up, so its answer reveals nothing about who has an account. Return
the invite's id and the link; whoever holds the link may redeem it.

```python
>>> from konklav_relying import fake_uuid7
>>> from konklav_relying.fake_ids import claimed_ms
>>> fake = fake_uuid7()
>>> fake.version
7
>>> claimed_ms(fake_uuid7(within=timedelta(days=365))) <= claimed_ms(fake_uuid7())
True

```

If the relying system's real ids fix some of the bits after the timestamp,
such as Python 3.14's `uuid.uuid7`, which seeds a counter whose top bit is
zero, the fakes differ there; make real ids the same way, or match the
fakes to them. A fake id helps only in an answer that is also paced.

A FastAPI application declares pacing on routes with `konklav-fastapi`'s
`RoutePacing` ([`items/py-fastapi`](../py-fastapi/README.md#pacing)).
The native Rust binding has the same helpers
(`konklav_relying_client::{pacing, fake_ids}`), and `konklav-axum` paces
axum routes with its `RoutePacing` layer.

### Rate limits

A `RateLimit` admits an event for a key only when every window admits it.
Each window lets `size` events through at once, and after that one more
each `period / size`:

```python
>>> import asyncio
>>> from datetime import timedelta
>>> from konklav_relying import RateLimit, RateLimited, RateLimitWindow
>>> login = RateLimit("login", [RateLimitWindow(size=2, period=timedelta(seconds=1))])
>>> async def three() -> None:
...     for _ in range(3):
...         await login.add("a@example.com")
>>> asyncio.run(three())
Traceback (most recent call last):
...
konklav_relying.rate_limit.RateLimited: rate limited; retry after ...

```

To share a limit between processes through Valkey or Redis (6.2 or later),
install the `redis` extra (`pip install konklav-relying[redis]`, the
client library for both) and pass a client and a secret of at
least 32 bytes that every process shares; keys reach the store only as keyed
hashes. Every process keeps counting in memory too, and answers from that
while the store fails or takes longer than `timeout` (100 ms by default). Set
`local_divisor` to the number of processes so that, answering from memory
together, they admit about the limit:

```python
login = RateLimit(
    "login",
    [RateLimitWindow(size=5, period=timedelta(minutes=1)), RateLimitWindow(size=20, period=timedelta(hours=1))],
    redis=redis.asyncio.Redis.from_url(redis_url),
    secret=rate_limit_secret,
    local_divisor=replicas,
)
```

Limits with the same name and windows share their state in the store.

## Running and testing

The crate is its own Cargo workspace, built by maturin.

```sh
mise run py:test    # build in place and run the tests
mise run py:build   # build the sdist and a wheel into dist/
```

- Direct coverage:
  - the core through the binding: decisions, revocations, flags, tenant facts, check fallback, input validation, DPoP proofs
  - route policies and typed results, with the doctests in this README and in `policy.py`, `results.py`, `pacing.py` and `fake_ids.py`
  - pacing (lower bounds only, so a loaded machine can't fail them; errors and cancellation) and fake ids (layout, random bits, claimed times)
  - the client against an httpx mock of Konklav with a live SSE feed: fallback, local decisions, invalidation, revocation, unknown sessions, erasure notices and reading the erased subjects

## Traceability and related docs

- [Relying SDK](../../docs/architecture/relying-sdk.md)
- [Relying core](../relying/README.md)
- [Software-item spec](../../docs/spec/software-items/py.md)
