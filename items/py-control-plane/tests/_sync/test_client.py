# Generated from ../_async by tools/generate.py; don't edit.
"""The client against an httpx mock of the control plane. The sync client's
copy in `tests/_sync` is generated from this file."""

import json

import httpx
import pytest

from konklav_control_plane import _backend, errors
from konklav_control_plane._sync.auth import BearerToken, SecretKey
from konklav_control_plane._sync.client import ControlPlaneClient

pytestmark = pytest.mark.anyio

URL = "https://konklav.example:8082"


def error(status, code, message="no", headers=None):
    return httpx.Response(status, json={"error": {"code": code, "message": message}}, headers=headers)


class Konklav:
    """Answers each request with the next of `responses` (a response, an
    exception to raise, or a function of the request), recording requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(request)
        # A fresh copy, since one may be answered more than once.
        return httpx.Response(response.status_code, headers=response.headers, content=response.content)

    def client(self, url=URL, auth=None, **options):
        return ControlPlaneClient(
            url,
            auth=auth or BearerToken("bootstrap"),
            http=httpx.Client(transport=httpx.MockTransport(self)),
            **options,
        )


@pytest.fixture
def waits(monkeypatch):
    """The client's sleeps, recorded instead of slept."""
    recorded = []

    def sleep(seconds):
        recorded.append(seconds)

    monkeypatch.setattr(_backend, "sync_sleep", sleep)
    return recorded


# r[verify item.py-control-plane.base-url]
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://konklav.example:8082", "https://konklav.example:8082/v1/tenants"),
        ("https://konklav.example:8082/", "https://konklav.example:8082/v1/tenants"),
        ("https://proxy.example/konklav/", "https://proxy.example/konklav/v1/tenants"),
    ],
)
def test_requests_go_under_v1_keeping_any_prefix(url, expected):
    konklav = Konklav(httpx.Response(200, json={"tenants": [], "next": None}))
    with konklav.client(url) as client:
        client.request("GET", "/tenants")
    assert str(konklav.requests[0].url) == expected


# r[verify item.py-control-plane.injectable-http]
# r[verify item.py-control-plane.explicit-config]
def test_sends_through_the_given_client_and_ignores_the_environment(monkeypatch):
    konklav = Konklav(httpx.Response(200, json={"id": "t"}))
    with konklav.client() as client:
        assert client.request("GET", "/tenants/t") == {"id": "t"}
    assert len(konklav.requests) == 1

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:1")
    with ControlPlaneClient(URL, auth=BearerToken("t")) as client:
        assert client._http.trust_env is False


# r[verify item.py-control-plane.auth]
def test_a_bearer_token_is_sent_as_is():
    konklav = Konklav(httpx.Response(200, json={}))
    with konklav.client(auth=BearerToken("bootstrap")) as client:
        client.request("GET", "/catalog")
    assert konklav.requests[0].headers["authorization"] == "Bearer bootstrap"


# r[verify item.py-control-plane.auth]
def test_a_token_function_is_asked_each_time():
    tokens = iter(["first", "second"])

    def token():
        return next(tokens)

    konklav = Konklav(httpx.Response(200, json={}), httpx.Response(200, json={}))
    with konklav.client(auth=token) as client:
        client.request("GET", "/catalog")
        client.request("GET", "/catalog")
    assert [r.headers["authorization"] for r in konklav.requests] == ["Bearer first", "Bearer second"]


# r[verify item.py-control-plane.auth]
def test_a_secret_key_logs_in_and_renews_at_80_percent(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(_backend, "now", lambda: clock[0])
    logins = iter(["one", "two"])

    def login(request):
        assert str(request.url) == "https://konklav.example:8080/v1/login/secret-key"
        assert "authorization" not in request.headers
        assert json.loads(request.content) == {"key_id": "key", "secret": "s3cret"}
        return httpx.Response(200, json={"access_token": next(logins), "expires_in": 100})

    ok = httpx.Response(200, json={})
    konklav = Konklav(login, ok, ok, login, ok)
    auth = SecretKey(subject_url="https://konklav.example:8080/", key_id="key", secret="s3cret")
    with konklav.client(auth=auth) as client:
        client.request("GET", "/catalog")
        clock[0] += 79
        client.request("GET", "/catalog")
        clock[0] += 2
        client.request("GET", "/catalog")
    sent = [r.headers.get("authorization") for r in konklav.requests]
    assert sent == [None, "Bearer one", "Bearer one", None, "Bearer two"]


# r[verify item.py-control-plane.auth-relogin]
def test_a_rejected_secret_key_token_logs_in_again_once():
    def login(request):
        return httpx.Response(200, json={"access_token": "token", "expires_in": 900})

    auth = SecretKey(subject_url=URL, key_id="key", secret="s3cret")
    konklav = Konklav(login, error(401, "UNAUTHENTICATED"), login, httpx.Response(200, json={"ok": True}))
    with konklav.client(auth=auth) as client:
        assert client.request("GET", "/catalog") == {"ok": True}

    konklav = Konklav(login, error(401, "UNAUTHENTICATED"), login, error(401, "UNAUTHENTICATED"))
    with konklav.client(auth=SecretKey(subject_url=URL, key_id="key", secret="s3cret")) as client:
        with pytest.raises(errors.Unauthenticated):
            client.request("GET", "/catalog")
    assert len(konklav.requests) == 4


# r[verify item.py-control-plane.auth-relogin]
def test_a_rejected_bearer_token_is_not_retried():
    konklav = Konklav(error(401, "UNAUTHENTICATED"))
    with konklav.client() as client:
        with pytest.raises(errors.Unauthenticated):
            client.request("GET", "/catalog")
    assert len(konklav.requests) == 1


# r[verify item.py-control-plane.errors]
@pytest.mark.parametrize(
    ("status", "code", "kind"),
    [
        (404, "NOT_FOUND", errors.NotFound),
        (409, "CONFLICT", errors.Conflict),
        (400, "INVALID_REQUEST", errors.InvalidRequest),
        (400, "METADATA_TOO_LARGE", errors.MetadataTooLarge),
        (412, "PRECONDITION_FAILED", errors.PreconditionFailed),
        (401, "UNAUTHENTICATED", errors.Unauthenticated),
        (401, "INVALID_CREDENTIALS", errors.Unauthenticated),
        (401, "SESSION_ENDED", errors.Unauthenticated),
        (403, "FORBIDDEN", errors.Forbidden),
        (429, "RATE_LIMITED", errors.RateLimited),
        (503, "OVERLOADED", errors.Unavailable),
        (503, "DATABASE_UNAVAILABLE", errors.Unavailable),
        (503, "MIGRATIONS_PENDING", errors.Unavailable),
        (503, "SIGNING_KEY_UNAVAILABLE", errors.Unavailable),
        (503, "CLAIMS_HOOK_UNAVAILABLE", errors.Unavailable),
        (500, "INTERNAL", errors.KonklavError),
        (418, "SOMETHING_NEW", errors.KonklavError),
    ],
)
def test_error_codes_raise_their_errors(status, code, kind):
    konklav = Konklav(error(status, code, "what happened"))
    with konklav.client(retries=0) as client:
        with pytest.raises(errors.KonklavError) as raised:
            client.request("POST", "/invites", json={})
    assert type(raised.value) is kind
    assert (raised.value.status, raised.value.code, raised.value.message) == (status, code, "what happened")
    assert raised.value.operation is None


# r[verify item.py-control-plane.errors]
def test_a_failed_batch_names_its_operation():
    failed = httpx.Response(404, json={"error": {"code": "NOT_FOUND", "message": "role not found", "operation": 2}})
    with Konklav(failed).client(retries=0) as client:
        with pytest.raises(errors.NotFound) as raised:
            client.batches.apply({"operations": []})
    assert raised.value.operation == 2
    assert "operation=2" in repr(raised.value)


# r[verify item.py-control-plane.errors]
def test_errors_without_an_envelope_or_a_response_have_no_code():
    konklav = Konklav(httpx.Response(502, text="Bad Gateway"), httpx.ConnectError("refused"))
    with konklav.client(retries=0) as client:
        with pytest.raises(errors.KonklavError) as raised:
            client.request("GET", "/catalog")
        assert (type(raised.value), raised.value.status, raised.value.code) == (errors.KonklavError, 502, None)
        with pytest.raises(errors.KonklavError) as raised:
            client.request("GET", "/catalog")
        assert (raised.value.status, raised.value.code) == (None, None)
        assert isinstance(raised.value.__cause__, httpx.ConnectError)


# r[verify item.py-control-plane.retry-after]
@pytest.mark.parametrize(("header", "seconds"), [("61", 61.0), ("1.5", 1.5), ("soon", None), (None, None)])
def test_rate_limits_carry_retry_after(header, seconds):
    headers = {"retry-after": header} if header else None
    konklav = Konklav(error(429, "RATE_LIMITED", headers=headers))
    with konklav.client(retries=0) as client:
        with pytest.raises(errors.RateLimited) as raised:
            client.request("GET", "/catalog")
    assert raised.value.retry_after == seconds


# r[verify item.py-control-plane.retries]
def test_rate_limits_are_retried_for_every_method_after_retry_after(waits):
    konklav = Konklav(
        error(429, "RATE_LIMITED", headers={"retry-after": "61"}),
        httpx.Response(201, json={"invite_id": "i"}),
    )
    with konklav.client() as client:
        assert client.request("POST", "/invites", json={}) == {"invite_id": "i"}
    assert waits == [61.0]


# r[verify item.py-control-plane.retries]
@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
@pytest.mark.parametrize(
    "failure",
    [
        error(503, "OVERLOADED"),
        error(503, "DATABASE_UNAVAILABLE"),
        error(503, "MIGRATIONS_PENDING"),
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
    ],
)
def test_idempotent_methods_are_retried_with_backoff(method, failure, waits):
    konklav = Konklav(failure, failure, httpx.Response(200, json={}))
    with konklav.client() as client:
        client.request(method, "/catalog")
    assert len(konklav.requests) == 3
    assert len(waits) == 2
    assert 0 <= waits[0] <= 0.5 and 0 <= waits[1] <= 1.0


# r[verify item.py-control-plane.retries]
def test_the_last_error_is_raised_once_attempts_run_out(waits):
    konklav = Konklav(*[error(503, "OVERLOADED", f"attempt {n}") for n in range(3)])
    with konklav.client(retries=2) as client:
        with pytest.raises(errors.Unavailable, match="attempt 2"):
            client.request("GET", "/catalog")
    assert len(waits) == 2


# r[verify item.py-control-plane.retries]
def test_zero_retries_sends_once(waits):
    konklav = Konklav(error(503, "OVERLOADED"))
    with konklav.client(retries=0) as client:
        with pytest.raises(errors.Unavailable):
            client.request("GET", "/catalog")
    assert (len(konklav.requests), waits) == (1, [])


# r[verify item.py-control-plane.retries]
def test_definite_errors_are_not_retried(waits):
    konklav = Konklav(error(404, "NOT_FOUND"))
    with konklav.client() as client:
        with pytest.raises(errors.NotFound):
            client.request("GET", "/tenants/x")
    assert len(konklav.requests) == 1


# r[verify item.py-control-plane.no-ambiguous-retry]
@pytest.mark.parametrize(
    "failure",
    [
        error(503, "OVERLOADED"),
        error(503, "DATABASE_UNAVAILABLE"),
        error(503, "MIGRATIONS_PENDING"),
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
    ],
)
def test_posts_are_not_retried_after_ambiguous_failures(failure, waits):
    konklav = Konklav(failure)
    with konklav.client() as client:
        with pytest.raises(errors.KonklavError):
            client.request("POST", "/invites", json={})
    assert (len(konklav.requests), waits) == (1, [])


# r[verify item.py-control-plane.write-cursor]
def test_writes_split_off_their_cursor():
    konklav = Konklav(
        httpx.Response(200, json={"id": "c", "cursor": 42}),
        httpx.Response(200, json={"id": "c"}),
    )
    with konklav.client() as client:
        written = client._write("PUT", "/catalog", json={})
        assert (written.value, written.cursor, written.created) == ({"id": "c"}, 42, None)
        written = client._write("PUT", "/catalog", json={})
        assert (written.value, written.cursor) == ({"id": "c"}, None)


# r[verify item.py-control-plane.last-cursor]
def test_the_client_remembers_its_highest_write_cursor():
    konklav = Konklav(
        httpx.Response(200, json={"id": "c", "cursor": 42}),
        httpx.Response(200, json={"id": "t"}),
        # An earlier write answering last, as concurrent writes may.
        httpx.Response(200, json={"id": "r", "cursor": 40}),
        batch_answer((201, {"id": "t", "cursor": 50}), cursor=50),
        httpx.Response(200, json={"subjects": [], "next": None, "cursor": 99}),
    )
    with konklav.client() as client:
        assert client.last_cursor is None
        client.catalog.put({"actions": []})
        assert client.last_cursor == 42
        client.tenants.set_facts("t", {})
        client.roles.put("t", "reader", {})
        assert client.last_cursor == 42
        with client.batch() as batch:
            batch.tenants.create("t", {})
        assert client.last_cursor == 50
        client.subjects.list()
        assert client.last_cursor == 50, "reads don't move it"


# r[verify item.py-control-plane.created]
def test_idempotent_creates_say_whether_they_created():
    konklav = Konklav(
        httpx.Response(201, json={"id": "t", "cursor": 7}),
        httpx.Response(200, json={"id": "t"}),
    )
    with konklav.client() as client:
        assert (client._write("PUT", "/tenants/t", json={}, create=True)).created is True
        assert (client._write("PUT", "/tenants/t", json={}, create=True)).created is False


# r[verify item.py-control-plane.paging]
def test_pages_are_followed_until_there_is_no_next():
    konklav = Konklav(
        httpx.Response(200, json={"subjects": [{"id": "a"}, {"id": "b"}], "next": "b"}),
        httpx.Response(200, json={"subjects": [{"id": "c"}], "next": None}),
    )
    with konklav.client() as client:
        ids = [subject["id"] for subject in client._pages("/subjects", "subjects", {"kind": "human", "limit": 2, "identifier": None})]
    assert ids == ["a", "b", "c"]
    queries = [dict(r.url.params) for r in konklav.requests]
    assert queries == [{"kind": "human", "limit": "2"}, {"kind": "human", "limit": "2", "before": "b"}]


def batch_answer(*results, cursor=None):
    body = {"results": [{"status": status, "body": body} for status, body in results]}
    if cursor is not None:
        body["cursor"] = cursor
    return httpx.Response(200, json=body)


# r[verify item.py-control-plane.batch]
def test_a_batch_sends_its_writes_in_one_request():
    konklav = Konklav(
        batch_answer(
            (201, {"id": "s", "kind": "human", "state": "active"}),
            (200, {"id": "m", "state": "active", "cursor": 7}),
            (200, {"id": "a", "role_id": "r", "cursor": 9}),
            cursor=9,
        )
    )
    with konklav.client() as client:
        with client.batch() as batch:
            subject = batch.subjects.create("s", {"kind": "human"})
            membership = batch.memberships.create("m", {"subject": "s", "tenant": "t"})
            assignment = batch.assignments.assign_to_membership("m", {"id": "a", "role": "reader"})
            with pytest.raises(RuntimeError):
                subject.result
            assert not konklav.requests, "nothing is sent before the block ends"
    (request,) = konklav.requests
    assert (request.method, request.url.path) == ("POST", "/v1/batch")
    assert json.loads(request.content) == {
        "operations": [
            {"method": "PUT", "path": "/subjects/s", "body": {"kind": "human"}},
            {"method": "PUT", "path": "/memberships/m", "body": {"subject": "s", "tenant": "t"}},
            {"method": "POST", "path": "/memberships/m/assignments", "body": {"id": "a", "role": "reader"}},
        ]
    }
    assert (subject.result.value["id"], subject.result.created) == ("s", True)
    assert (membership.result.cursor, membership.result.created) == (7, False)
    assert assignment.result.cursor == 9
    assert batch.cursor == 9


# r[verify item.py-control-plane.batch]
def test_a_batch_holds_only_writes_and_is_sent_once():
    konklav = Konklav(batch_answer((200, {"id": "app", "client_secret": "s3cret"})))
    with konklav.client() as client:
        batch = client.batch()
        with pytest.raises(TypeError):
            batch.tenants.get("t")
        secret = batch.oidc_clients.new_secret("app")
        batch.send()
        assert secret.result["client_secret"] == "s3cret"
        with pytest.raises(RuntimeError):
            batch.tenants.create("t", {})
        with pytest.raises(RuntimeError):
            batch.send()
        with client.batch():
            pass
    assert len(konklav.requests) == 1, "an empty batch sends nothing"


# r[verify item.py-control-plane.batch]
def test_a_batch_is_not_sent_when_its_block_raises():
    konklav = Konklav()
    with konklav.client() as client:
        with pytest.raises(ValueError):
            with client.batch() as batch:
                batch.subjects.create("s", {"kind": "human"})
                raise ValueError
    assert not konklav.requests


# r[verify item.py-control-plane.batch]
# r[verify item.py-control-plane.errors]
def test_a_failed_batch_raises_its_operations_error():
    failed = httpx.Response(403, json={"error": {"code": "FORBIDDEN", "message": "no", "operation": 1}})
    with Konklav(failed).client() as client:
        with pytest.raises(errors.Forbidden) as raised:
            with client.batch() as batch:
                batch.tenants.create("t", {})
                created = batch.subjects.create("s", {"kind": "human"})
    assert raised.value.operation == 1
    with pytest.raises(RuntimeError):
        created.result


# r[verify item.py-control-plane.retries]
# r[verify item.py-control-plane.no-ambiguous-retry]
def test_only_batches_with_a_key_are_retried_after_an_ambiguous_failure(waits):
    konklav = Konklav(error(503, "OVERLOADED"), batch_answer((201, {"id": "t"})))
    with konklav.client() as client:
        with client.batch(idempotency_key="k", idempotency_seconds=60) as batch:
            created = batch.tenants.create("t", {})
    assert created.result.created is True
    assert len(konklav.requests) == 2 and len(waits) == 1
    sent = json.loads(konklav.requests[0].content)
    assert (sent["idempotency_key"], sent["idempotency_seconds"]) == ("k", 60)

    konklav = Konklav(error(503, "OVERLOADED"))
    with konklav.client() as client:
        with pytest.raises(errors.Unavailable):
            with client.batch() as batch:
                batch.tenants.create("t", {})
    assert len(konklav.requests) == 1


# r[verify metadata.write.precondition]
def test_a_metadata_patch_sends_its_precondition_as_if_match():
    answer = lambda request: httpx.Response(200, json={"id": "i", "metadata": {}, "cursor": 3})  # noqa: E731
    konklav = Konklav(answer, answer)
    with konklav.client() as client:
        written = client.invites.patch_metadata("i", {"tenant_id": None}, if_match="abc")
        client.invites.patch_metadata("i", {"tenant_id": "t"})
    first, second = konklav.requests
    assert (first.method, first.url.path) == ("PATCH", "/v1/invites/i/metadata")
    assert first.headers["if-match"] == '"abc"'
    assert json.loads(first.content) == {"tenant_id": None}, "null removes a key"
    assert "if-match" not in second.headers
    assert written.cursor == 3


# r[verify metadata.write.precondition]
def test_a_batched_metadata_patch_carries_its_precondition():
    konklav = Konklav(batch_answer((200, {"id": "s", "metadata": {"a": 1}}), cursor=4))
    with konklav.client() as client:
        with client.batch() as batch:
            batch.subjects.patch_metadata("s", {"a": 1}, if_match="e1")
    (request,) = konklav.requests
    assert json.loads(request.content) == {
        "operations": [
            {"method": "PATCH", "path": "/subjects/s/metadata", "body": {"a": 1}, "if_match": "e1"},
        ]
    }


# r[verify metadata.filter]
def test_metadata_filters_are_sent_as_a_json_object():
    konklav = Konklav(lambda request: httpx.Response(200, json={"invites": [], "next": None}))
    with konklav.client() as client:
        client.invites.list(tenant="root", metadata={"tenant_id": "t-1", "seats": 3})
    (request,) = konklav.requests
    assert dict(request.url.params) == {"tenant": "root", "metadata": '{"seats":3,"tenant_id":"t-1"}'}
