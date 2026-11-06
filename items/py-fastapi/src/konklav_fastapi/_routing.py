"""
How FastAPI keeps the routes of included routers, read in one place.

Since 0.140, `include_router` no longer copies routes. The application's
routes hold the included router itself, and FastAPI derives a context per
inclusion with the combined dependencies:

- an included HTTP route stays the router's own `APIRoute`; the request's
  `scope["fastapi"]["effective_route_context"]` carries that inclusion's
  combined dependencies, and `scope["route"]` is the original route;
- an included websocket route is rebuilt as a new `APIWebSocketRoute` with
  the combined dependencies, which is the request's `scope["route"]`, and
  the context's own list stays empty.

`APIRouter.add_api_route` copies the router's own dependencies in front of
the route's, so a route's own dependencies are what follows them.
"""

# r[impl item.py-fastapi.fastapi-range]
# What this module reads is why pyproject.toml bounds the FastAPI versions.
from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.params import Depends
from fastapi.requests import HTTPConnection
from fastapi.routing import APIRoute, APIRouter, APIWebSocketRoute, iter_route_contexts
from starlette.routing import BaseRoute

_SCOPE_KEY = "fastapi"
_CONTEXT_KEY = "effective_route_context"


@dataclass(frozen=True)
class ServedRoute:
    """One route as FastAPI serves it, once per inclusion."""

    original: APIRoute | APIWebSocketRoute
    """The route as its router declared it."""
    dependencies: Sequence[Depends]
    """Every layer's, outermost first."""
    own_dependencies: Sequence[Depends]
    """The route's own, without its router's."""
    path_format: str
    methods: frozenset[str]
    """Empty for a websocket."""
    path_parameters: frozenset[str]
    dependant: Dependant | None

    @property
    def is_websocket(self) -> bool:
        return isinstance(self.original, APIWebSocketRoute)

    @property
    def label(self) -> str:
        return f"{','.join(sorted(self.methods)) or 'WEBSOCKET'} {self.path_format}"


def owners(router: APIRouter) -> dict[int, tuple[BaseRoute, APIRouter]]:
    """Each API and websocket route by `id`, with the router that declared it."""
    found: dict[int, tuple[BaseRoute, APIRouter]] = {}
    for route in router.routes:
        included = getattr(route, "original_router", None)
        if isinstance(included, APIRouter):
            found.update(owners(included))
        elif isinstance(route, APIRoute | APIWebSocketRoute):
            found[id(route)] = (route, router)
    return found


def own_dependencies(route: APIRoute | APIWebSocketRoute, router: APIRouter | None) -> Sequence[Depends]:
    declared = list(route.dependencies)
    inherited = list(router.dependencies) if router is not None else []
    if declared[: len(inherited)] == inherited:
        return declared[len(inherited) :]
    # The router's dependencies changed after the route was added: nothing
    # can be told apart, so nothing counts as the route's own.
    return []


def served_routes(app: FastAPI) -> Iterator[ServedRoute]:
    """Every API and websocket route of `app`, once per inclusion."""
    owner = owners(app.router)
    for context in iter_route_contexts(app.routes):
        original = context.original_route
        if not isinstance(original, APIRoute | APIWebSocketRoute):
            continue
        served: Any = context
        if isinstance(original, APIWebSocketRoute):
            # 0.143 forwards to the inclusion's context, later versions to
            # the rebuilt route.
            rebuilt = getattr(context, "starlette_route", None)
            if isinstance(rebuilt, APIWebSocketRoute):
                served = rebuilt
        _, router = owner.get(id(original), (original, None))
        yield ServedRoute(
            original=original,
            dependencies=list(served.dependencies),
            own_dependencies=own_dependencies(original, router),
            path_format=served.path_format,
            methods=frozenset(getattr(served, "methods", None) or ()) if isinstance(original, APIRoute) else frozenset(),
            path_parameters=frozenset(served.param_convertors),
            dependant=getattr(served, "dependant", None) or original.dependant,
        )


def requested(connection: HTTPConnection) -> tuple[APIRoute | APIWebSocketRoute, Sequence[Depends]] | None:
    """The original route serving `connection` and its combined dependencies."""
    scope = connection.scope
    route = scope.get("route")
    context: Any = scope.get(_SCOPE_KEY, {}).get(_CONTEXT_KEY)
    if isinstance(route, APIWebSocketRoute):
        original = context.original_route if context is not None and context.starlette_route is route else route
        return (original, route.dependencies) if isinstance(original, APIWebSocketRoute) else None
    if isinstance(route, APIRoute):
        if context is not None and context.original_route is route:
            return route, context.dependencies
        return route, route.dependencies
    return None


def dependency_calls(dependant: Dependant | None) -> Iterator[Callable[..., Any]]:
    if dependant is None:
        return
    if dependant.call is not None:
        yield dependant.call
    for dependency in dependant.dependencies:
        yield from dependency_calls(dependency)
