"""
Rate limits on FastAPI routes, with `konklav_relying.RateLimit`.

`RouteRateLimit(limit, key)` is a dependency that adds one event per
request. `key` is either a template or a dependency of its own:

- a template of literal text and `{source:name}` fields:
  - `{path:project}`: a path parameter;
  - `{token:sub}`: a claim of the verified token (`sub`, `sid`, `knd`, or
    `tid` on routes that admit only tenant tokens);
  - `{client:address}`: the client's address (`KonklavRoutes.client_address`,
    which honours `trusted_proxies`);
  - `{{` and `}}` for literal braces;
- a callable, resolved as a FastAPI dependency (so it can depend on
  others), returning `str` or `bytes`.

Code inside a handler can call `limit.add(...)` directly. Either way,
`konklav_relying.RateLimited` is answered by `handle_rate_limited`, which
`KonklavRoutes.install` registers.

```python
login = RateLimit("login", [RateLimitWindow(size=5, period=timedelta(minutes=1))])
exports = RateLimit("export", [RateLimitWindow(size=10, period=timedelta(hours=1))])


@app.post("/login", dependencies=[RoutePolicy.public(), RouteRateLimit(login, "{client:address}")])
async def log_in(form: LoginForm) -> ...:
    await login.add(form.email)  # and per address, in code
    ...


@router.post("/projects/{project}/export", dependencies=[RouteRateLimit(exports, "{token:sub}/{path:project}")])
async def export(project: str) -> ...: ...
```
"""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi.params import Depends
from fastapi.requests import HTTPConnection
from konklav_relying import AccessToken, RateLimit

from konklav_fastapi.errors import handle_rate_limited
from konklav_fastapi.routes import KonklavRoutes, _current_token

__all__ = ["RouteRateLimit", "handle_rate_limited"]

TOKEN_CLAIMS = frozenset({"sub", "sid", "knd", "tid"})
"""The claims a template can name: those a verified token always has (`tid` on tenant tokens)."""

_FIELD = re.compile(r"\{([a-z]+):([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True)
class _Field:
    source: str
    name: str

    def __str__(self) -> str:
        return f"{{{self.source}:{self.name}}}"


type _Part = str | _Field


# r[impl item.py-fastapi.rate-limit-template]
def _parse(template: str) -> tuple[_Part, ...]:
    parts: list[_Part] = []
    literal: list[str] = []
    at = 0

    def refuse(why: str) -> ValueError:
        return ValueError(f"rate-limit key template {template!r}: {why}")

    while at < len(template):
        if template.startswith(("{{", "}}"), at):
            literal.append(template[at])
            at += 2
        elif template[at] == "{":
            match = _FIELD.match(template, at)
            if match is None:
                raise refuse(f"expected {{source:name}} at {at}")
            field = _Field(match[1], match[2])
            if field.source == "path":
                pass
            elif field.source == "token":
                if field.name not in TOKEN_CLAIMS:
                    raise refuse(f"{field}: a token claim must be one of {', '.join(sorted(TOKEN_CLAIMS))}")
            elif field.source == "client":
                if field.name != "address":
                    raise refuse(f"{field}: the only client field is {{client:address}}")
            else:
                raise refuse(f"{field}: the source must be path, token or client")
            if literal:
                parts.append("".join(literal))
                literal.clear()
            parts.append(field)
            at = match.end()
        elif template[at] == "}":
            raise refuse(f"unmatched '}}' at {at}; write '}}}}' for a literal one")
        else:
            literal.append(template[at])
            at += 1
    if literal:
        parts.append("".join(literal))
    return tuple(parts)


def _render(parts: Sequence[_Part], connection: HTTPConnection, token: AccessToken | None) -> str:
    values: list[str] = []
    for part in parts:
        if isinstance(part, str):
            values.append(part)
        elif part.source == "path":
            values.append(str(connection.path_params[part.name]))
        elif part.source == "token":
            assert token is not None
            value = getattr(token, part.name)
            if value is None:
                # Startup validation rules this out; never share one key.
                raise RuntimeError(f"the verified token has no `{part.name}` for the rate-limit key")
            values.append(str(value))
        else:
            address = KonklavRoutes.of(connection).client_address(connection)
            if address is None:
                # r[impl item.py-fastapi.client-address]
                raise RuntimeError("the connection has no client address for the rate-limit key")
            values.append(address)
    # A JSON array, so that different values can't render the same key.
    return json.dumps(values, separators=(",", ":"))


# r[impl item.py-fastapi.rate-limit]
class RouteRateLimit(Depends):
    """
    A dependency adding one event to `limit` per request, for the key that
    `key` gives: a template, or a dependency returning `str` or `bytes`.
    """

    def __init__(self, limit: RateLimit, key: str | Callable[..., Any]) -> None:
        self.limit = limit
        self.key = key
        self._parts: tuple[_Part, ...] | None = None
        if isinstance(key, str):
            self._parts = parts = _parse(key)
            uses_token = any(isinstance(part, _Field) and part.source == "token" for part in parts)

            async def add_templated(connection: HTTPConnection, token: AccessToken | None = None) -> None:
                await limit.add(_render(parts, connection, token))

            parameters = [inspect.Parameter("connection", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=HTTPConnection)]
            if uses_token:
                # The token the route's policy verified, not verified again.
                parameters.append(
                    inspect.Parameter(
                        "token",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        annotation=Annotated[AccessToken, Depends(_current_token)],
                    )
                )
            dependency: Callable[..., Any] = add_templated
        else:

            async def add_keyed(value: Any) -> None:
                if not isinstance(value, str | bytes):
                    raise TypeError(
                        f"rate-limit key for {limit.name!r} must be str or bytes, not {type(value).__name__}"
                    )
                await limit.add(value)

            parameters = [
                inspect.Parameter("value", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Annotated[Any, Depends(key)])
            ]
            dependency = add_keyed
        # Set directly: with postponed annotations FastAPI would have to
        # resolve these from strings, and they are local to this call.
        setattr(dependency, "__signature__", inspect.Signature(parameters, return_annotation=None))
        super().__init__(dependency=dependency)

    def __repr__(self) -> str:
        return f"RouteRateLimit({self.limit!r}, key={self.key!r})"

    # r[impl item.py-fastapi.rate-limit-template-validation]
    def _route_problem(self, path_parameters: frozenset[str], admitted: frozenset[str] | None) -> str | None:
        """
        Why this limit's template can't be rendered on a route with these
        path parameters, admitting these token kinds (`None` when public).
        """
        for part in self._parts or ():
            if not isinstance(part, _Field):
                continue
            if part.source == "path" and part.name not in path_parameters:
                return f"rate limit {self.limit.name!r} uses {part}, but the route has no `{part.name}` path parameter"
            if part.source == "token":
                if admitted is None:
                    return f"rate limit {self.limit.name!r} uses {part}, but its policy is public"
                if part.name == "tid" and not admitted <= {"tenant"}:
                    return (
                        f"rate limit {self.limit.name!r} uses {part}, which only tenant tokens carry, "
                        f"but its policy admits {', '.join(sorted(admitted))}"
                    )
        return None
