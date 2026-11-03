"""The synchronous control-plane client, with the same methods, arguments,
results and errors as `konklav_control_plane.ControlPlaneClient`."""

from ._common import Written
from ._sync.auth import BearerToken, SecretKey
from ._sync.client import ControlPlaneClient

__all__ = ["BearerToken", "ControlPlaneClient", "SecretKey", "Written"]
