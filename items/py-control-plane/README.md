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
  timeouts only for `GET`, `PUT`, `DELETE` and batches with an idempotency
  key.
- A method for every operation in the API document, grouped as it tags
  them: `client.tenants`, `memberships`, `subjects`, `credentials`,
  `sessions`, `signing_keys`, `catalog`, `templates`, `roles`,
  `assignments`, `entitlements`, `explain`, `shares`,
  `registered_scopes`, `invites`, `oidc_clients`, `imports` and
  `batches`. Path arguments come first, then the request body as `body`,
  then query parameters by keyword. `request` sends anything else.
- Batches: `client.batch()` collects writes through the same namespaces
  and sends them as one all-or-nothing request (`Batch`, `Pending`). The
  namespaces are generic over a `Mode`, so on a batch a write is typed as
  a `Pending` of what it returns on the client, and reads don't
  type-check.
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

Several writes can be applied in one request, all or nothing. Later ones
name what earlier ones create by the ids chosen for them:

```python
async with client.batch(idempotency_key=key) as batch:
    batch.subjects.create(person, {"kind": "human"})
    batch.credentials.create(person, {"kind": "password", "identifier": email, "password": password})
    batch.memberships.create(membership, {"subject": person, "tenant": tenant_id})
    assigned = batch.assignments.assign_to_membership(membership, {"id": assignment, "role": "reader"})
# Sent on leaving the block; nothing is sent if the block raises.
print(assigned.result.value["id"], batch.cursor)
```

If an operation fails, nothing is applied and its error is raised with its
position as `error.operation`. With an `idempotency_key`, sending the same
batch again answers what it first answered, so the client retries it like
a `PUT`; secrets the first answer showed are generated anew.

For read-your-writes with `konklav-relying`, pass `written.cursor` (or a
batch's `cursor`) to `RelyingClient.await_cursor`; see
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
its tools and `tests/typing`.

- Direct coverage:
  - both clients against an `httpx` mock of the control plane (the sync
    tests are generated from the async ones): URLs, the injected client,
    each way to authenticate and re-login, the error mapping,
    `Retry-After`, which failures are retried and which aren't, write
    cursors, created-or-found, paging, and batches (what they send, their
    results, failures, and retries with and without a key);
  - `tests/typing/batches.py`, checked by `mypy`: writes keep their types
    on the client and are `Pending` on a batch, and reads on a batch don't
    type-check;
  - every operation in the API document has a method on both clients,
    which sends the operation's method and path;
  - both clients have the same methods and arguments;
  - the generated types are `TypedDict`s of the decoded JSON;
  - the package is pure Python, typed, and neither requires nor imports
    `konklav-relying`.
- Integration coverage (`tests/integration`): every method against a real
  server, with the async client, an operator holding only
  `konklav:tenants:manage` refused elsewhere, repeated creates reporting
  `created`, and batches: references to earlier creates, a failure that
  applies nothing, and a repeated idempotency key showing new secrets. The `test-server` binary from
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
