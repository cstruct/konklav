# konklav-py-control-plane (`konklav-control-plane` on PyPI)

The Python control-plane client: a pure-Python package for managing Konklav
through its control-plane surface.

It has a method for every control-plane operation. Nothing publishes it to
PyPI yet.

## Responsibilities

- `ControlPlaneClient` (async, over `httpx.AsyncClient`) and
  `konklav_control_plane.sync.ControlPlaneClient` (over `httpx.Client`).
  The sync client is generated from the async source by `unasync`
  (`tools/generate.py`) and committed, as are its tests.
- Authentication with `BearerToken`, `SecretKey` (logs in at the
  subject-facing surface, renews at 80% of the token's lifetime, and logs in
  again once if the token is rejected) or a function returning the token.
- Errors: `KonklavError` and a subclass per kind of failure, by error code.
- Retries: `RATE_LIMITED` for every method; `OVERLOADED`,
  `DATABASE_UNAVAILABLE`, `MIGRATIONS_PENDING`, connection errors and
  timeouts only for `GET`, `PUT` and `DELETE`.
- A method for every operation in the API document, grouped as it tags
  them: `client.tenants`, `memberships`, `subjects`, `credentials`,
  `sessions`, `signing_keys`, `catalog`, `templates`, `roles`,
  `assignments`, `entitlements`, `explain`, `shares`,
  `registered_scopes`, `invites`, `oidc_clients` and `imports`. Path
  arguments come first, then the request body as `body`, then query
  parameters by keyword. `request` sends anything else.
- `Written`: a write's result with its change-feed cursor, and whether an
  idempotent create created. The paged lists (`tenants`, `subjects`,
  `sessions`) also have `iter`, which follows every page.
- `konklav_control_plane.types`: `TypedDict`s generated from the
  control-plane API document (`items/server/openapi/control-plane.json`).

Out of scope:

- Authorization decisions, which belong to `konklav-relying`
  ([`items/py`](../py/README.md)). Neither package depends on the other.
- Reading configuration files or environment variables: URLs and
  credentials are always arguments.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-server` | Serves the control-plane surface this package calls; only the same version is supported |
| `konklav-api` | Its API document is the source of this package's types; this package doesn't use the crate |
| `konklav-py` (`konklav-relying`) | Independent: neither depends on the other |

## Usage

```python
from konklav_control_plane import ControlPlaneClient, SecretKey

auth = SecretKey(subject_url="https://konklav:8080", key_id=key_id, secret=secret)
async with ControlPlaneClient("https://konklav:8082", auth=auth) as client:
    written = await client.tenants.create(tenant_id, {"facts": {"tenant_type": "client"}})
    print(written.created, written.cursor)
    async for subject in client.subjects.iter(kind="human"):
        ...
```

The sync client is the same from `konklav_control_plane.sync`, without
`await` and `async`.

For read-your-writes with `konklav-relying`, pass `written.cursor` to
`RelyingClient.await_cursor`; see
[`examples/python/read_your_writes.py`](../../examples/python/read_your_writes.py).

## Running

This is a library and can't run on its own.

## Testing

```sh
mise run py-control-plane:test          # the unit tests
mise run py-control-plane:integration   # against servers on fresh databases
mise run py-control-plane:generate   # regenerate types.py and the sync code
mise run py-control-plane:build      # build the sdist and wheel into dist/
```

`mise run lint` fails when the generated files are stale, for example after
the API document changes, and runs `mypy --strict` over the package and
its tools.

- Direct coverage:
  - both clients against an `httpx` mock of the control plane (the sync
    tests are generated from the async ones): URLs, the injected client,
    each way to authenticate and re-login, the error mapping,
    `Retry-After`, which failures are retried and which aren't, write
    cursors, created-or-found, and paging;
  - every operation in the API document has a method on both clients,
    which sends the operation's method and path;
  - both clients have the same methods and arguments;
  - the generated types are `TypedDict`s of the decoded JSON;
  - the package is pure Python, typed, and neither requires nor imports
    `konklav-relying`.
- Integration coverage (`tests/integration`): every method against a real
  server, with the async client, and an operator holding only
  `konklav:tenants:manage` refused elsewhere. The `test-server` binary from
  `examples/` starts each server on a fresh database; the tests are skipped
  unless `KONKLAV_TEST_SERVER` names it, as the mise task does. `mise run
  test` runs them, and so does `ci.yml`.
- CI builds the wheel and sdist and runs the unit tests against each
  installed (`.github/workflows/python.yml`).

## Traceability and related docs

- [Item spec](../../docs/spec/software-items/py-control-plane.md)
- [Nomenclature](../../docs/nomenclature.md) (`control-plane client`)
- [Control-plane API document](../server/openapi/control-plane.json)
- [Releases](../../CONTRIBUTING.md#releases)
