# konklav-py (`konklav-relying` on PyPI)

Python bindings for the relying core, plus an asyncio/httpx host.

## Responsibilities

- `konklav_relying._core.Core`: pyo3 bindings over `konklav-relying`. Values cross as JSON strings and times as Unix ms.
- `konklav_relying.RelyingClient`: the Python I/O layer.
  - Logs in as a service principal and follows the change feed.
  - Runs background refreshes.
  - Decides locally, falling back to `/v1/check` when caches can't be trusted.
  - Offers `await_cursor` for read-your-writes.

No decision logic lives in Python.

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

## Running and testing

The crate is its own Cargo workspace, built by maturin.

```sh
mise run py:test    # build in place and run the tests
mise run py:build   # build the sdist and a wheel into dist/
```

- Direct coverage:
  - the core through the binding: decisions, revocations, flags, check fallback, input validation
  - the client against an httpx mock of Konklav with a live SSE feed: fallback, local decisions, invalidation, revocation, unknown sessions

## Traceability and related docs

- [Relying SDK](../../docs/architecture/relying-sdk.md)
- [Relying core](../relying/README.md)
