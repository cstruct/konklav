# konklav-control-plane

Manage [Konklav](https://github.com/cstruct/konklav) from Python.

Konklav is a standalone identity and access service. This package is
the Python client for its control plane, the API operators and automation
use to manage tenants, subjects, credentials, roles, shares and the rest.

```python
from konklav_control_plane import ControlPlaneClient, SecretKey

auth = SecretKey(subject_url="https://konklav:8080", key_id=key_id, secret=secret)
async with ControlPlaneClient("https://konklav:8082", auth=auth) as client:
    written = await client.tenants.create(tenant_id, {"facts": {}})
```

Every control-plane operation has a method, with request and response
types generated from Konklav's API document. `konklav_control_plane.sync`
has the same client for synchronous code. Failed requests are retried
where that's safe, and errors raise `KonklavError` subclasses such as
`NotFound` and `Forbidden`.

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
