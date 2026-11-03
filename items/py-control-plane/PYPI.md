# konklav-control-plane

Manage [Konklav](https://github.com/cstruct/konklav) from Python.

Konklav is a standalone identity and access service. This package will be
the Python client for its control plane, the API operators and automation
use to manage tenants, subjects, credentials, roles, shares and the rest.

**This release has no client yet.** It reserves the package name and
version while the client is built; see the
[plan](https://github.com/cstruct/konklav/tree/main/items/py-control-plane)
for its status.

To decide authorization in a relying system, use
[`konklav-relying`](https://pypi.org/project/konklav-relying/) instead. The
two packages don't depend on each other.

## Versions

The package has the same version as the Konklav server it was released
with, and only that server version is supported. Pre-releases, such as
`1.3.0rc1`, are installed only with `pip install --pre`.

## Links

- [Konklav](https://github.com/cstruct/konklav)
- [This package's README](https://github.com/cstruct/konklav/tree/main/items/py-control-plane)
- [Releases and changelog](https://github.com/cstruct/konklav/releases)
- [Issues](https://github.com/cstruct/konklav/issues)

MIT licensed.
