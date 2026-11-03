# Python Control-Plane Client Software Item

Stable implementation contracts owned by `konklav-py-control-plane`, the
Python control-plane client, published as `konklav-control-plane` and
imported as `konklav_control_plane`.

## Packaging

r[item.py-control-plane.pure-python]
The package MUST contain no native code, so that one `py3-none-any` wheel
installs on every platform and Python version it supports.

r[item.py-control-plane.independent]
`konklav-control-plane` MUST NOT require or import `konklav-relying`, and
`konklav-relying` MUST NOT require or import `konklav-control-plane`, so
that a relying system and an operator's tooling each install only what they
use.

r[item.py-control-plane.same-version]
The package MUST carry the version of the Konklav release it was built
with. It is supported only against a server of that version; it MUST NOT
promise to work against any other.

r[item.py-control-plane.explicit-config]
The client MUST take its URLs and credentials as arguments only. It MUST
NOT read environment variables or configuration files.

## Clients

r[item.py-control-plane.async-default]
`konklav_control_plane.ControlPlaneClient` MUST be asynchronous, built on
`httpx.AsyncClient`.

r[item.py-control-plane.sync-parity]
`konklav_control_plane.sync.ControlPlaneClient` MUST offer the same methods,
arguments, results and errors as the asynchronous client, over
`httpx.Client`. It MUST be generated from the asynchronous source, and CI
MUST fail when the committed generated code differs from a fresh
generation.

r[item.py-control-plane.injectable-http]
Both clients MUST accept an `httpx` client to send requests through, so
that callers control transports, proxies, TLS and timeouts, and tests can
use a mock transport.

r[item.py-control-plane.base-url]
The client MUST take the control-plane surface's base URL without `/v1`
and MUST keep any path prefix it has, so that a surface served behind a
proxy under a prefix is reached at `<prefix>/v1/...`.

r[item.py-control-plane.whole-surface]
Every operation in the control-plane API document MUST have a client
method, and CI MUST fail when an operation has none.

## Types

r[item.py-control-plane.types]
The request and response types MUST be `TypedDict`s generated from the
committed control-plane API document
(`items/server/openapi/control-plane.json`), and CI MUST fail when the
committed types differ from a fresh generation. Responses MUST be returned
as the decoded JSON itself, without conversion: enums stay strings and
timestamps stay RFC 3339 strings.

## Authentication

r[item.py-control-plane.auth]
The client MUST support three ways to authenticate, each sending
`Authorization: Bearer <token>`:

- a fixed bearer token, such as the bootstrap token or an operator's access
  token;
- a service principal's secret key, logged in at the subject-facing
  surface's `/v1/login/secret-key` and logged in again before the access
  token expires, once 80% of its lifetime has passed;
- a caller-supplied callable that returns the token to send.

r[item.py-control-plane.auth-relogin]
When the control plane answers `UNAUTHENTICATED` to a request sent with a
token the client obtained from a secret key, the client MUST log in again
and retry that request once. It MUST NOT retry it more than once.

## Errors

r[item.py-control-plane.errors]
Every error response MUST raise `KonklavError`, or a subclass of it,
carrying the HTTP status, the `code` and the `message` from the error
envelope. The codes are those of the API document's `ErrorCode` schema.
Callers branch on the subclass or `code`, never on `message`. The
subclasses are:

| Subclass | Codes |
|---|---|
| `NotFound` | `NOT_FOUND` |
| `Conflict` | `CONFLICT` |
| `InvalidRequest` | `INVALID_REQUEST` |
| `Unauthenticated` | `UNAUTHENTICATED`, `INVALID_CREDENTIALS`, `SESSION_ENDED` |
| `Forbidden` | `FORBIDDEN` |
| `RateLimited` | `RATE_LIMITED` |
| `Unavailable` | `OVERLOADED`, `DATABASE_UNAVAILABLE`, `MIGRATIONS_PENDING`, `SIGNING_KEY_UNAVAILABLE`, `CLAIMS_HOOK_UNAVAILABLE` |

A code not in this table, a response without the error envelope, and a
request that got no response (a connection error or timeout) MUST raise
`KonklavError` itself. Without the envelope `code` is `None`, and without a
response `status` is `None` too, with the `httpx` error as the cause.

r[item.py-control-plane.retry-after]
`RateLimited` MUST expose the response's `Retry-After` header as a number
of seconds, or `None` when it is absent or not a number of seconds.

## Retries

r[item.py-control-plane.retries]
The client MUST retry failed requests by default, with a caller-set number
of attempts, where zero turns retries off. Between attempts it MUST wait
the `Retry-After` the response carries, or else back off exponentially with
random jitter. When the attempts run out, it MUST raise the last error.
What it retries:

- `RATE_LIMITED`, for every method: the server refuses before doing any
  work.
- `OVERLOADED`, `DATABASE_UNAVAILABLE` and `MIGRATIONS_PENDING`, connection
  errors and timeouts, only for `GET`, `PUT` and `DELETE`, which are
  idempotent on the control-plane surface.

r[item.py-control-plane.no-ambiguous-retry]
The client MUST NOT retry a `POST` after a failure that may have come after
the server acted on it: `OVERLOADED` (which the server also answers when a
request times out), `DATABASE_UNAVAILABLE`, `MIGRATIONS_PENDING`, a timeout,
or a connection error once the request may have been sent.

## Results

r[item.py-control-plane.write-cursor]
A method for an operation that answers with a write cursor MUST return a
`Written` with the resource as `value`, without the `cursor` field, and the
cursor as `cursor` (an `int`, or `None` when the write produced no event).
The cursor MUST be usable unchanged with `konklav-relying`'s
`RelyingClient.await_cursor`.

r[item.py-control-plane.created]
A method for an idempotent create (any create taking a caller-chosen id,
`platform.idempotency.client-ids`) MUST report whether the server created
the resource (`201`) or found it already there with the same content
(`200`).

r[item.py-control-plane.paging]
A method for a paged operation MUST return one page, including its `next`
marker, and the client MUST also offer an iterator over every item that
requests page after page, passing `next` as `before`, until a page has no
`next`.
