# konklav-py-control-plane (`konklav-control-plane` on PyPI)

The Python control-plane client: a pure-Python package for managing Konklav
through its control-plane surface.

So far it is only a skeleton, so that packaging and release problems show
up before the client exists. Nothing publishes it to PyPI yet.

## Responsibilities

- Reserves the `konklav-control-plane` distribution and the
  `konklav_control_plane` import package, typed (`py.typed`).
- Carries the release version, which `mise run release:bump` sets and the
  release workflow checks against the tag.

Planned: an async client with an opt-in sync variant, authentication with a
bearer token or a service principal's secret key, typed errors, retries,
paging, and request and response types generated from the control-plane
API document (`items/server/openapi/control-plane.json`).

Out of scope:

- Authorization decisions, which belong to `konklav-relying`
  ([`items/py`](../py/README.md)). Neither package depends on the other.
- Reading configuration files or environment variables: URLs and
  credentials are always arguments.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-server` | Serves the control-plane surface this package calls; only the same version is supported |
| `konklav-api` | Its API document is the source of this package's types (planned); this package doesn't use the crate |
| `konklav-py` (`konklav-relying`) | Independent: neither depends on the other |

## Running

This is a library and can't run on its own.

## Testing

```sh
mise run py-control-plane:test    # sync the environment and run the tests
mise run py-control-plane:build   # build the sdist and wheel into dist/
```

- Direct coverage: the package's version comes from its distribution, it
  is typed, and it neither requires nor imports `konklav-relying`.
- CI builds the wheel and sdist and runs the tests against each installed
  (`.github/workflows/python.yml`).

## Traceability and related docs

- [Nomenclature](../../docs/nomenclature.md) (`control-plane client`)
- [Control-plane API document](../server/openapi/control-plane.json)
- [Releases](../../CONTRIBUTING.md#releases)
