"""
What evaluating a route's policy can end in, other than an allow.

Each outcome is an exception, a subclass of `KonklavDenied`.
`KonklavRoutes.install` registers `handle_denied` for them, which answers
HTTP requests with the status and a JSON body and closes websockets with
code 1008. To answer differently, register your own handler for
`KonklavDenied` (or a subclass) after installing:

```python
routes.install(app)
app.add_exception_handler(Forbidden, my_forbidden_handler)
```
"""

from __future__ import annotations

import math
import secrets
from typing import Any, ClassVar

from fastapi.requests import HTTPConnection
from fastapi.responses import JSONResponse
from fastapi.websockets import WebSocket
from konklav_relying import DenyReason, RateLimited, StepUp

__all__ = [
    "Forbidden",
    "KonklavDenied",
    "KonklavUnavailable",
    "RoutePolicyError",
    "StepUpRequired",
    "Unauthenticated",
    "handle_denied",
    "handle_rate_limited",
    "retry_after_seconds",
]


class RoutePolicyError(ValueError):
    """Routes whose policies can't be evaluated, found by startup validation."""


# r[impl item.py-fastapi.outcomes]
class KonklavDenied(Exception):
    """A request the route's policy doesn't allow."""

    status_code: ClassVar[int] = 403
    code: str

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @property
    def headers(self) -> dict[str, str]:
        return {}

    def body(self) -> dict[str, Any]:
        return {"error": {"code": self.code}}


class Unauthenticated(KonklavDenied):
    """
    No usable token: `missing_token`, `invalid_token` or
    `invalid_dpop_proof`, with a `WWW-Authenticate` challenge. A refused
    token is challenged in the scheme it was presented with (`scheme`, `DPoP`
    or `Bearer`), a refused proof always with `DPoP`, and a missing token
    with both.
    """

    status_code = 401

    def __init__(self, code: str, scheme: str | None = None) -> None:
        super().__init__(code)
        self.scheme = scheme

    @property
    def headers(self) -> dict[str, str]:
        if self.code == "invalid_dpop_proof":
            return {"WWW-Authenticate": 'DPoP error="invalid_dpop_proof"'}
        if self.scheme is None:
            return {"WWW-Authenticate": "Bearer, DPoP"}
        return {"WWW-Authenticate": f'{self.scheme} error="{self.code}"'}


class Forbidden(KonklavDenied):
    """
    A deny: `reason` is the decision's, or `token_tenant` when the route's
    tenant isn't the token's.
    """

    status_code = 403

    def __init__(self, reason: DenyReason) -> None:
        super().__init__(reason.code)
        self.reason = reason

    def body(self) -> dict[str, Any]:
        # As Konklav writes deny reasons: a bare code, or the code with its fields.
        details = dict(self.reason.details)
        reason: Any = {self.reason.code: details} if details else self.reason.code
        return {"error": {"code": "forbidden", "reason": reason}}


class StepUpRequired(KonklavDenied):
    """
    Fresher or stronger authentication would allow the request: `step_up`
    says what. Challenged in the token's `scheme` with
    `error="insufficient_user_authentication"` (RFC 9470), and `max_age` when
    the requirement has one. The methods it needs are `amr` values, which the
    challenge's `acr_values` can't carry, so they are only in the body.
    """

    status_code = 401

    def __init__(self, step_up: StepUp, scheme: str = "Bearer") -> None:
        super().__init__("step_up")
        self.step_up = step_up
        self.scheme = scheme

    @property
    def headers(self) -> dict[str, str]:
        challenge = f'{self.scheme} error="insufficient_user_authentication"'
        if self.step_up.max_age_seconds is not None:
            challenge += f", max_age={self.step_up.max_age_seconds}"
        return {"WWW-Authenticate": challenge}

    def body(self) -> dict[str, Any]:
        return {"error": {"code": "step_up", "requirement": self.step_up.to_json()}}


class KonklavUnavailable(KonklavDenied):
    """No decision could be reached, so the request is denied (fails closed)."""

    status_code = 503

    def __init__(self) -> None:
        super().__init__("konklav_unavailable")


async def handle_denied(connection: HTTPConnection, error: Exception) -> JSONResponse | None:
    """The default handler: a JSON answer, or for a websocket, a close with 1008."""
    assert isinstance(error, KonklavDenied)
    if isinstance(connection, WebSocket):
        await connection.close(code=1008, reason=error.code)
        return None
    return JSONResponse(error.body(), status_code=error.status_code, headers=error.headers)


# Websocket close code 1013: try again later.
_TRY_AGAIN_LATER = 1013


def retry_after_seconds(error: RateLimited) -> int:
    """
    The `Retry-After` value for `error`: its wait in whole seconds, rounded
    up, plus random jitter of up to a tenth of it (at least a second), so
    clients refused together don't all retry together.
    """
    seconds = max(1, math.ceil(error.retry_after.total_seconds()))
    return seconds + secrets.randbelow(max(1, seconds // 10) + 1)


# r[impl item.py-fastapi.rate-limited]
async def handle_rate_limited(connection: HTTPConnection, error: Exception) -> JSONResponse | None:
    """
    Answers `konklav_relying.RateLimited`: 429 with `Retry-After`
    (`retry_after_seconds`), or for a websocket, a close with 1013 (try
    again later).
    """
    assert isinstance(error, RateLimited)
    if isinstance(connection, WebSocket):
        await connection.close(code=_TRY_AGAIN_LATER, reason="rate_limited")
        return None
    return JSONResponse(
        {"error": {"code": "rate_limited"}},
        status_code=429,
        headers={"Retry-After": str(retry_after_seconds(error))},
    )
