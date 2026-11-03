# Generated from ../_async by tools/generate.py; don't edit.
"""How the client authenticates to the control plane."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .. import _backend
from .._backend import SyncLock, SyncToken
from .._common import base

if TYPE_CHECKING:
    from .client import ControlPlaneClient


@runtime_checkable
class Auth(Protocol):
    def token(self, client: ControlPlaneClient) -> str:
        """The bearer token to send."""
        ...

    def invalidate(self) -> bool:
        """Forgets a rejected token; `True` if the next one will differ."""
        ...


# r[impl item.py-control-plane.auth]
class BearerToken:
    """A fixed token: the bootstrap token, or an operator's access token."""

    def __init__(self, token: str) -> None:
        self._token = token

    def token(self, client: ControlPlaneClient) -> str:
        return self._token

    def invalidate(self) -> bool:
        return False


class SecretKey:
    """A service principal's secret key, logged in at the subject-facing
    surface and logged in again once 80% of the token's lifetime has
    passed."""

    def __init__(self, *, subject_url: str, key_id: str, secret: str) -> None:
        self._login_url = f"{base(subject_url)}/v1/login/secret-key"
        self._key_id = key_id
        self._secret = secret
        self._cached: tuple[str, float] | None = None
        self._lock = SyncLock()

    def token(self, client: ControlPlaneClient) -> str:
        with self._lock:
            if self._cached is not None and self._cached[1] > _backend.now():
                return self._cached[0]
            response = client._send(
                "POST",
                self._login_url,
                json={"key_id": self._key_id, "secret": self._secret},
                authenticate=False,
            )
            body = response.json()
            renew_at = _backend.now() + body["expires_in"] * 0.8
            self._cached = (body["access_token"], renew_at)
            return self._cached[0]

    def invalidate(self) -> bool:
        self._cached = None
        return True


class TokenFunction:
    """A caller's function that returns the token to send."""

    def __init__(self, function: Callable[[], SyncToken]) -> None:
        self._function = function

    def token(self, client: ControlPlaneClient) -> str:
        token = self._function()
        if inspect.isawaitable(token):
            token = token
        if not isinstance(token, str):
            raise TypeError(f"the token function returned {type(token).__name__}, not str")
        return token

    def invalidate(self) -> bool:
        return False


def resolve(auth: Auth | Callable[[], SyncToken]) -> Auth:
    if isinstance(auth, Auth):
        return auth
    return TokenFunction(auth)
