# konklav-py (`konklav-relying` on PyPI)

Python bindings for the relying core, plus an asyncio/httpx host.

## Responsibilities

- `konklav_relying._core.Core`: pyo3 bindings over `konklav-relying`. Values cross as JSON strings and times as Unix ms.
- `konklav_relying.RelyingClient`: the Python I/O layer.
  - Logs in as a service principal and follows the change feed.
  - Runs background refreshes.
  - Decides locally, falling back to `/v1/check` when caches can't be trusted.
  - Offers `await_cursor` for read-your-writes.
- `konklav_relying.policy`: route policies (`Policy`, `StepUp`), which state an operation's requirements with scope ids unresolved, merge across nested layers and resolve to the requirements JSON. Frozen dataclasses and the standard library only, so framework integrations can build on it.
- `konklav_relying.results`: typed results (`Decision`, `DenyReason`, `AccessToken`) read from the JSON the core and Konklav return.

No decision logic lives in Python: a route policy only builds requirements.

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
    audience="api",
)
await client.start()
decision = await client.decide(token, {"scopes": [{"kind": "project", "id": project_id, "actions": ["document:read"]}]})
```

For sender-constrained (DPoP) tokens, `decide_request` and `verify_request` take the request's raw `Authorization` and `DPoP` headers, its method, and the public URL the client addressed (behind a proxy, not the upstream one). A deny with reason `invalid_dpop_proof`, or `InvalidDpopProof` from `verify_request`, should be answered with 401 and `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.

A request's DPoP proof is answered once, so a host that needs the verified token before it can state the requirements doesn't call `verify_request` and then `decide_request`. Instead it calls `accept_request`, which verifies the token, its session and its proof and returns an `AcceptedRequest` with the `AccessToken`, then decides once with `decide_accepted` (or `decide_accepted_typed`). That decision rechecks the session but not the proof.

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

## Running and testing

The crate is its own Cargo workspace, built by maturin.

```sh
mise run py:test    # build in place and run the tests
mise run py:build   # build the sdist and a wheel into dist/
```

- Direct coverage:
  - the core through the binding: decisions, revocations, flags, tenant facts, check fallback, input validation, DPoP proofs
  - route policies and typed results, with the doctests in this README and in `policy.py` and `results.py`
  - the client against an httpx mock of Konklav with a live SSE feed: fallback, local decisions, invalidation, revocation, unknown sessions

## Traceability and related docs

- [Relying SDK](../../docs/architecture/relying-sdk.md)
- [Relying core](../relying/README.md)
- [Software-item spec](../../docs/spec/software-items/py.md)
