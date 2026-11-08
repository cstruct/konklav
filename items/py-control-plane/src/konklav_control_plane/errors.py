"""The errors the control-plane clients raise."""

from __future__ import annotations

import httpx


class KonklavError(Exception):
    """Konklav answered with an error, or couldn't be reached.

    Branch on the subclass or `code`, never on `message`. `status` and
    `code` are `None` when no response arrived, and `code` is `None` when
    the response had no error envelope. For a failed batch, `operation` is
    the failing operation's position, counted from zero.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
        operation: int | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.operation = operation

    def __repr__(self) -> str:
        operation = "" if self.operation is None else f", operation={self.operation!r}"
        return (
            f"{type(self).__name__}(status={self.status!r}, code={self.code!r}, "
            f"message={self.message!r}{operation})"
        )


class NotFound(KonklavError):
    """`NOT_FOUND`."""


class Conflict(KonklavError):
    """`CONFLICT`."""


class InvalidRequest(KonklavError):
    """`INVALID_REQUEST`."""


class MetadataTooLarge(InvalidRequest):
    """`METADATA_TOO_LARGE`: the write would leave an object's metadata over
    the server's size limit."""


class PreconditionFailed(KonklavError):
    """`PRECONDITION_FAILED`: the metadata changed since the `metadata_etag`
    given as `if_match` was read. Read it again and redo the change."""


class Unauthenticated(KonklavError):
    """`UNAUTHENTICATED`, `INVALID_CREDENTIALS` or `SESSION_ENDED`."""


class Forbidden(KonklavError):
    """`FORBIDDEN`: the caller lacks the operation's capability."""


class RateLimited(KonklavError):
    """`RATE_LIMITED`. `retry_after` is in seconds, when the server said."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
        operation: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, status=status, code=code, operation=operation)
        self.retry_after = retry_after


class Unavailable(KonklavError):
    """Konklav or something it needs is overloaded or down for now."""


# r[impl item.py-control-plane.errors]
_BY_CODE: dict[str, type[KonklavError]] = {
    "NOT_FOUND": NotFound,
    "CONFLICT": Conflict,
    "INVALID_REQUEST": InvalidRequest,
    "METADATA_TOO_LARGE": MetadataTooLarge,
    "PRECONDITION_FAILED": PreconditionFailed,
    "UNAUTHENTICATED": Unauthenticated,
    "INVALID_CREDENTIALS": Unauthenticated,
    "SESSION_ENDED": Unauthenticated,
    "FORBIDDEN": Forbidden,
    "RATE_LIMITED": RateLimited,
    "OVERLOADED": Unavailable,
    "DATABASE_UNAVAILABLE": Unavailable,
    "MIGRATIONS_PENDING": Unavailable,
    "SIGNING_KEY_UNAVAILABLE": Unavailable,
    "CLAIMS_HOOK_UNAVAILABLE": Unavailable,
}


def from_response(response: httpx.Response) -> KonklavError:
    """The error an unsuccessful response stands for."""
    try:
        body = response.json()
        code = body["error"]["code"]
        message = body["error"]["message"]
        operation = body["error"].get("operation")
        if not isinstance(code, str) or not isinstance(message, str):
            raise TypeError
        if operation is not None and not isinstance(operation, int):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        return KonklavError(
            f"HTTP {response.status_code} without an error body", status=response.status_code
        )
    kind = _BY_CODE.get(code, KonklavError)
    if kind is RateLimited:
        return RateLimited(
            message,
            status=response.status_code,
            code=code,
            operation=operation,
            retry_after=_retry_after(response.headers.get("retry-after")),
        )
    return kind(message, status=response.status_code, code=code, operation=operation)


# r[impl item.py-control-plane.retry-after]
def _retry_after(value: str | None) -> float | None:
    """`Retry-After` in seconds; HTTP dates aren't supported."""
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if seconds >= 0 else None
