"""A client for Konklav's control-plane surface.

`ControlPlaneClient` is asynchronous; `konklav_control_plane.sync` has the
same client for synchronous code. Request and response types are in
`konklav_control_plane.types`, and errors in `konklav_control_plane.errors`.
"""

# r[impl item.py-control-plane.pure-python]
# r[impl item.py-control-plane.independent]
from importlib.metadata import version

from ._async.auth import BearerToken, SecretKey
# r[impl item.py-control-plane.async-default]
from ._async.client import ControlPlaneClient
from ._common import Written
from .errors import (
    Conflict,
    Forbidden,
    InvalidRequest,
    KonklavError,
    NotFound,
    RateLimited,
    Unauthenticated,
    Unavailable,
)

__version__ = version("konklav-control-plane")

__all__ = [
    "BearerToken",
    "Conflict",
    "ControlPlaneClient",
    "Forbidden",
    "InvalidRequest",
    "KonklavError",
    "NotFound",
    "RateLimited",
    "SecretKey",
    "Unauthenticated",
    "Unavailable",
    "Written",
]
