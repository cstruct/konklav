# Generated from ../_async by tools/generate.py; don't edit.
"""Every operation in the API document has a method that calls it. The sync
client's copy in `tests/_sync` is generated from this file."""

import inspect
import json
import pathlib
import re

import httpx
import pytest

from konklav_control_plane._sync.auth import BearerToken
from konklav_control_plane._sync.client import ControlPlaneClient

pytestmark = pytest.mark.anyio

DOCUMENT = json.loads(
    (pathlib.Path(__file__).resolve().parents[3] / "server" / "openapi" / "control-plane.json").read_text()
)
OPERATIONS = {
    operation["operationId"]: (method.upper(), template, operation)
    for template, item in DOCUMENT["paths"].items()
    for method, operation in item.items()
}


def methods(client):
    """Each marked method of the client's namespaces, by operation id."""
    found = {}
    for namespace_name, namespace in vars(client).items():
        if namespace_name.startswith("_"):
            continue
        for name, method in inspect.getmembers(namespace, inspect.ismethod):
            operation = getattr(method, "__konklav_operation__", None)
            if operation is not None:
                assert operation not in found, f"{operation} has two methods"
                found[operation] = (f"{namespace_name}.{name}", method)
    return found


def client_for(handler):
    return ControlPlaneClient(
        "https://konklav.example:8082",
        auth=BearerToken("t"),
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )


# r[verify item.py-control-plane.whole-surface]
def test_every_operation_has_a_method():
    with client_for(lambda request: httpx.Response(200)) as client:
        assert sorted(methods(client)) == sorted(OPERATIONS)


def arguments(method):
    """Placeholder arguments for every required parameter."""
    positional, keywords = [], {}
    for parameter in inspect.signature(method).parameters.values():
        if parameter.default is not inspect.Parameter.empty:
            continue
        value = {} if parameter.name == "body" else f"x-{parameter.name}"
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            keywords[parameter.name] = value
        else:
            positional.append(value)
    return positional, keywords


# r[verify item.py-control-plane.whole-surface]
@pytest.mark.parametrize("operation_id", sorted(OPERATIONS))
def test_each_method_calls_its_operation(operation_id):
    expected_method, template, operation = OPERATIONS[operation_id]
    status = int(min(code for code in operation["responses"] if code != "default"))
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(status, json={})

    with client_for(handler) as client:
        name, method = methods(client)[operation_id]
        positional, keywords = arguments(method)
        method(*positional, **keywords)
    (request,) = requests
    pattern = re.sub(r"\{[^}]+\}", "[^/]+", template)
    assert request.method == expected_method, name
    assert re.fullmatch(pattern, request.url.path), f"{name} sent {request.url.path}, not {template}"
    required = {p["name"] for p in operation.get("parameters", []) if p["in"] == "query" and p.get("required")}
    assert required <= set(request.url.params), name


def test_ids_stay_one_path_segment():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    with client_for(handler) as client:
        client.roles.get("root", "ops/admin")
        client.registered_scopes.remove("document", "a b")
    assert [r.url.raw_path for r in requests] == [
        b"/v1/tenants/root/roles/ops%2Fadmin",
        b"/v1/registered-scopes/document/a%20b",
    ]


# r[verify item.py-control-plane.created]
# r[verify item.py-control-plane.write-cursor]
def test_creates_and_writes_return_written():
    responses = [
        httpx.Response(201, json={"id": "t", "state": "active", "cursor": 5}),
        httpx.Response(200, json={"id": "t", "state": "active"}),
        httpx.Response(200, json={"key": "reader", "cursor": 6}),
    ]
    with client_for(lambda request: responses.pop(0)) as client:
        created = client.tenants.create("t", {})
        found = client.tenants.create("t", {})
        role = client.roles.put("root", "reader", {"policies": []})
    assert (created.value, created.cursor, created.created) == ({"id": "t", "state": "active"}, 5, True)
    assert (found.cursor, found.created) == (None, False)
    assert (role.value, role.cursor, role.created) == ({"key": "reader"}, 6, None)


# r[verify item.py-control-plane.paging]
def test_iterating_follows_every_page():
    pages = [
        httpx.Response(200, json={"tenants": [{"id": "a"}], "next": "a"}),
        httpx.Response(200, json={"tenants": [{"id": "b"}], "next": None}),
    ]
    requests = []

    def handler(request):
        requests.append(request)
        return pages.pop(0)

    with client_for(handler) as client:
        ids = [tenant["id"] for tenant in client.tenants.iter(parent="root", limit=1)]
    assert ids == ["a", "b"]
    assert [dict(r.url.params) for r in requests] == [
        {"parent": "root", "limit": "1"},
        {"parent": "root", "limit": "1", "before": "a"},
    ]


def test_unset_query_parameters_are_left_out():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"sessions": [], "next": None})

    with client_for(handler) as client:
        client.sessions.list(subject="s", active=True)
    assert dict(requests[0].url.params) == {"subject": "s", "active": "true"}
