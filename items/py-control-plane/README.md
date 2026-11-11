# konklav-py-control-plane (`konklav-control-plane` on PyPI)

The Python control-plane client: a pure-Python package for managing Konklav
through its control-plane surface.

It has a method for every control-plane operation, and batches of them.
Each release publishes it to PyPI.

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
  idempotent create created. `last_cursor` is the highest cursor the
  client's writes and batches have answered with. The paged lists (`tenants`, `subjects`,
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

### Installing

```sh
pip install konklav-control-plane==<server version>
```

Install the version of the Konklav server you call: only that version is
supported, since the methods and types come from that server's API
document. To try unreleased changes, install it from a checkout
(`pip install ./items/py-control-plane`) or from the wheel that
`mise run py-control-plane:build` writes to `dist/`.

### Clients

```python
from konklav_control_plane import ControlPlaneClient, SecretKey

auth = SecretKey(subject_url="https://konklav:8080", key_id=key_id, secret=secret)
async with ControlPlaneClient("https://konklav:8082", auth=auth) as client:
    written = await client.tenants.create(tenant_id, {"facts": {"tenant_type": "client"}})
    print(written.created, written.cursor)
    async for subject in client.subjects.iter(kind="human"):
        ...
```

`url` is the control-plane surface without `/v1`. The sync client is the
same from `konklav_control_plane.sync`, without `await` and `async`:

```python
from konklav_control_plane.sync import ControlPlaneClient

with ControlPlaneClient("https://konklav:8082", auth=auth) as client:
    tenant = client.tenants.get(tenant_id)
```

Pass `http=` to send through your own `httpx.AsyncClient` (or
`httpx.Client`), for example for mTLS or a proxy; the client then doesn't
close it. Nothing is read from the environment.

### Authenticating

- `BearerToken(token)`: a token you already hold, such as the bootstrap
  token while setting up the first operator.
- `SecretKey(subject_url=..., key_id=..., secret=...)`: a service
  principal's secret key. The client logs in at the subject-facing
  surface, renews the token at 80% of its lifetime, and logs in again once
  if the token is rejected.
- A function returning the token (or, for the async client, an awaitable
  of it), called before each request.

The caller needs the capability of each area it calls, such as
`konklav:tenants:manage`; `konklav:control:all` covers them all.

### Operations

Path arguments come first, then the body, then query parameters by
keyword. Bodies and results are `TypedDict`s from
`konklav_control_plane.types`.

```python
# Tenants and memberships
await client.tenants.create(tenant, {"templates": ["reader"]})
await client.memberships.create(membership, {"subject": person, "tenant": tenant})
page = await client.tenants.list(parent="root", limit=50)

# Subjects and credentials
await client.subjects.create(person, {"kind": "human"})
await client.credentials.create(person, {"id": credential, "kind": "password", "identifier": email, "password": pw})
key = await client.credentials.create(service, {"kind": "secret_key"})  # key.value["secret_keys"], shown once
await client.credentials.rotate_slot(key.value["credential"]["id"], "b")
await client.subjects.disable(person)  # ends the subject's sessions
report = await client.subjects.personal_data(person)  # what Konklav holds about it, without secrets
await client.subjects.erase(person)  # removes its personal data, for good

# Catalog, templates, roles and assignments
await client.catalog.put({"actions": [{"name": "document:read"}]})
await client.roles.put(tenant, "reader", {"policies": [{"action": "document:read", "effect": "allow"}]})
await client.assignments.assign_to_membership(membership, {"id": assignment, "role": "reader"})
await client.assignments.assign_global(operator, {"role": "konklav.admin"})
await client.entitlements.get(person, tenant=tenant)
await client.explain.entitlement(person, action="document:read", tenant=tenant)

# Shares, registered scopes and invites
await client.shares.offer(share, {"owner": a, "recipient": b, "scope": {"kind": "project", "id": "p-1"}, "actions": ["document:read"]})
await client.registered_scopes.record("document", "d-1", {"tenant": tenant})
await client.invites.create({"id": invite, "email": "new@example.com", "tenant": tenant, "roles": ["reader"]})

# Sessions, signing keys, OIDC clients and imports
await client.sessions.revoke({"subject": person})
await client.oidc_clients.put("app", {"kind": "confidential", "redirect_uris": [...], "scopes": ["openid"], "audience": "app"})
await client.imports.subjects({"subjects": [{"id": person, "kind": "human"}]})
```

`client.request(method, path, json=..., params=...)` sends anything else
and returns the decoded body.

### Writes, cursors and repeats

Writes that produce change-feed events return a `Written`: the resource as
`value` and the cursor of the last event as `cursor`. Every create takes an
id you choose and is idempotent on it; its `Written.created` says whether
this call created the resource (`True`) or found it already there with the
same content (`False`). Repeating a secret-key create shows new secrets.

For read-your-writes with `konklav-relying`, pass `written.cursor` (or a
batch's `cursor`) to `RelyingClient.await_cursor`; see
[`examples/python/read_your_writes.py`](../../examples/python/read_your_writes.py).
To wait for every write a client has made, such as before answering a
request that made several, pass `client.last_cursor` instead: the highest
cursor its writes and batches have answered with, or `None` before any
has. It never decreases, whatever order concurrent writes answer in.

```python
if client.last_cursor is not None:
    await relying.await_cursor(client.last_cursor)
```

### Batches

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

A batch's namespaces have the client's writes and no reads. Each call
returns a `Pending` whose `result` is what the same call on the client
returns, once the batch has been sent. If an operation fails, nothing is
applied and its error is raised with its position as `error.operation`.
With an `idempotency_key`, sending the same batch again answers what it
first answered without applying it again; secrets the first answer showed
are generated anew.

### Errors

Every error response raises `KonklavError` or a subclass, with `status`,
`code` and `message`. Branch on the subclass or `code`, never on
`message`.

| Subclass | Codes |
|---|---|
| `NotFound` | `NOT_FOUND` |
| `Conflict` | `CONFLICT` |
| `InvalidRequest` | `INVALID_REQUEST` |
| `Unauthenticated` | `UNAUTHENTICATED`, `INVALID_CREDENTIALS`, `SESSION_ENDED` |
| `Forbidden` | `FORBIDDEN` |
| `RateLimited` | `RATE_LIMITED`, with `retry_after` in seconds |
| `Unavailable` | `OVERLOADED`, `DATABASE_UNAVAILABLE`, `MIGRATIONS_PENDING`, `SIGNING_KEY_UNAVAILABLE`, `CLAIMS_HOOK_UNAVAILABLE` |

Other codes raise `KonklavError` itself. A request that got no response
raises `KonklavError` with `status` and `code` set to `None` and the
`httpx` error as its cause.

### Retries

`retries` (3 by default; `0` turns them off) is how many times a failed
request is sent again, waiting `Retry-After` when the server sends it and
otherwise backing off exponentially with jitter:

- `RATE_LIMITED`, for every method: the server refused before doing
  anything.
- `OVERLOADED`, `DATABASE_UNAVAILABLE`, `MIGRATIONS_PENDING`, timeouts and
  connection errors only for `GET`, `PUT`, `DELETE` and batches with an
  idempotency key, which can't be applied twice. A `POST` that may have
  been applied is never sent again: give creates an id, and repeat them
  yourself, which is safe.

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
    cursors and `last_cursor`, created-or-found, paging, and batches (what they send, their
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
