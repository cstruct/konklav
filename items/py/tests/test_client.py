import asyncio
import uuid
from typing import Any

import httpx
import pytest

from konklav_relying import (
    AccessToken,
    Decision,
    DenyReason,
    Erased,
    ErasureNotice,
    ErasuresMissed,
    InvalidDpopProof,
    KonklavError,
    Policy,
    RelyingClient,
)
from support import AUDIENCE, ISSUER, DpopKey, FakeKonklav, Keys


def client_for(fake: FakeKonklav, **audiences: Any) -> RelyingClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake.handle))
    return RelyingClient(
        relying_url="http://konklav",
        subject_url="http://konklav",
        key_id="key",
        secret="secret",
        issuer=ISSUER,
        **(audiences or {"audience": AUDIENCE}),
        http=http,
        heartbeat_ms=500,
        debounce_ms=50,
    )


async def until_trusted(client: RelyingClient) -> None:
    for _ in range(200):
        if client.is_trusted():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the feed never connected")


def test_falls_back_to_check_then_decides_locally_and_follows_the_feed() -> None:
    async def scenario() -> None:
        keys = Keys()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        client = client_for(fake)
        token = keys.token(subject=subject, session=session, tenant=tenant)
        requirements = {"tenant": ["project:read"]}

        # Before the feed is up, the check API answers.
        assert await client.decide(token, requirements) == {"decision": "allow"}
        assert "/v1/check" in fake.calls

        await client.start()
        try:
            await until_trusted(client)
            fake.calls.clear()
            assert await client.decide(token, requirements) == {"decision": "allow"}
            assert "/v1/check" not in fake.calls, "decided locally"

            # An entitlement change reaches the client through the feed.
            fake.actions = []
            fake.revision = 2
            cursor = fake.push("entitlements.changed", {"subjects": [subject]})
            assert await client.await_cursor(cursor)
            decision = await client.decide(token, requirements)
            assert decision["reason"] == {"missing_actions": {"actions": ["project:read"]}}

            # So does a revocation, without any debounce.
            fake.session_revoked = True
            fake.session_version = 2
            cursor = fake.push("session.changed", fake.session_state())
            assert await client.await_cursor(cursor)
            assert await client.decide(token, requirements) == {"decision": "deny", "reason": "invalid_token"}
        finally:
            await client.stop()

    asyncio.run(scenario())


def test_tokens_for_unknown_sessions_are_denied() -> None:
    async def scenario() -> None:
        keys = Keys()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        client = client_for(fake)
        await client.start()
        try:
            await until_trusted(client)
            token = keys.token(subject=subject, session=str(uuid.uuid4()), tenant=tenant)
            assert await client.decide(token, {}) == {"decision": "deny", "reason": "invalid_token"}
        finally:
            await client.stop()

    asyncio.run(scenario())


# r[verify item.py.audiences]
# r[verify relying.verify.audiences]
def test_accepts_tokens_for_any_of_its_audiences() -> None:
    async def scenario() -> None:
        keys = Keys()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        client = client_for(fake, audiences={AUDIENCE, "app"})
        assert client.audiences == {AUDIENCE, "app"}
        app = keys.token(subject=subject, session=session, tenant=tenant, audience="app")
        other = keys.token(subject=subject, session=session, tenant=tenant, audience="other")
        requirements = {"tenant": ["project:read"]}

        # Before the feed is up, the check API is told the audiences.
        assert await client.decide(app, requirements) == {"decision": "allow"}
        assert fake.checks[-1]["audiences"] == sorted([AUDIENCE, "app"])
        assert (await client.decide(other, requirements))["reason"] == "invalid_token"
        unchecked = await client.verify_typed(app)
        assert unchecked is not None and unchecked.aud == "app"

        await client.start()
        try:
            await until_trusted(client)
            fake.calls.clear()
            for audience in (AUDIENCE, "app"):
                token = keys.token(subject=subject, session=session, tenant=tenant, audience=audience)
                verified = await client.verify_typed(token)
                assert verified is not None and verified.aud == audience
                assert await client.decide(token, requirements) == {"decision": "allow"}
            assert await client.verify(other) is None
            assert (await client.decide(other, requirements))["reason"] == "invalid_token"
            assert "/v1/check" not in fake.calls, "decided locally"
        finally:
            await client.stop()

    asyncio.run(scenario())


def test_audiences_are_one_or_a_collection() -> None:
    fake = FakeKonklav(Keys(), "s", "t", "x")
    assert client_for(fake, audience="api").audiences == {"api"}
    with pytest.raises(TypeError, match="either audience or audiences"):
        client_for(fake, audience="api", audiences={"app"})
    with pytest.raises(TypeError, match="either audience or audiences"):
        client_for(fake, audience=None)
    with pytest.raises(TypeError, match="not a string"):
        client_for(fake, audiences="api")
    with pytest.raises(ValueError, match="empty"):
        client_for(fake, audiences=set())


def test_verifies_tokens_and_reads_entitlements() -> None:
    async def scenario() -> None:
        keys = Keys()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        client = client_for(fake)
        await client.start()
        try:
            await until_trusted(client)
            token = keys.token(subject=subject, session=session, tenant=tenant)
            claims = await client.verify(token)
            assert claims is not None and claims["sid"] == session
            assert await client.verify(keys.token(subject=subject, session=session, tenant=tenant, version=0)) is None
            stranger = Keys().token(subject=subject, session=session, tenant=tenant)
            assert await client.verify(stranger) is None
            entitlements = await client.entitlements(subject, tenant)
            assert entitlements["tenant"] == ["project:read"]
        finally:
            await client.stop()

    asyncio.run(scenario())


def test_decides_and_verifies_requests_with_dpop_proofs() -> None:
    async def scenario() -> None:
        keys = Keys()
        key = DpopKey()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        client = client_for(fake)
        await client.start()
        try:
            await until_trusted(client)
            token = keys.token(subject=subject, session=session, tenant=tenant, jkt=key.jkt())
            url = "https://api.example/projects/1"
            decision = await client.decide_request(
                authorization=f"DPoP {token}",
                dpop=key.proof("GET", url, token),
                method="GET",
                url=url,
                requirements={"tenant": ["project:read"]},
            )
            assert decision == {"decision": "allow"}
            claims = await client.verify_request(
                authorization=f"DPoP {token}", dpop=key.proof("GET", url, token), method="GET", url=url
            )
            assert claims is not None and claims["cnf"] == {"jkt": key.jkt()}
            with pytest.raises(InvalidDpopProof):
                await client.verify(token)
            denied = await client.decide(token, {"tenant": ["project:read"]})
            assert denied == {"decision": "deny", "reason": "invalid_dpop_proof"}
        finally:
            await client.stop()

    asyncio.run(scenario())


# r[verify item.py.accepted-request]
# r[verify relying.verify.accepted-presentation]
def test_accepted_requests_are_decided_once_with_their_one_proof() -> None:
    async def scenario() -> None:
        keys = Keys()
        key = DpopKey()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        client = client_for(fake)
        token = keys.token(subject=subject, session=session, tenant=tenant, jkt=key.jkt())
        url = "https://api.example/projects/1"
        reading = {"tenant": ["project:read"]}

        def headers() -> dict[str, str]:
            return {"authorization": f"DPoP {token}", "dpop": key.proof("GET", url, token), "method": "GET", "url": url}

        # Before the feed is up, the check API verifies and decides.
        accepted = await client.accept_request(**headers())
        assert accepted is not None and accepted.token.sid == session
        assert await client.decide_accepted(accepted, reading) == {"decision": "allow"}
        assert fake.calls.count("/v1/check") == 2

        await client.start()
        try:
            await until_trusted(client)
            fake.calls.clear()
            once = headers()
            accepted = await client.accept_request(**once)
            assert accepted is not None and accepted.token.cnf is not None
            decision = await client.decide_accepted_typed(accepted, reading)
            assert decision.allowed and "/v1/check" not in fake.calls
            # It decides as often as the request needs, until released; its
            # proof never works again.
            assert await client.decide_accepted(accepted, reading) == {"decision": "allow"}
            client.release_accepted(accepted)
            assert await client.decide_accepted(accepted, reading) == {"decision": "deny", "reason": "invalid_token"}
            with pytest.raises(InvalidDpopProof):
                await client.accept_request(**once)
            stranger = Keys().token(subject=subject, session=session, tenant=tenant)
            assert await client.accept_request(authorization=f"Bearer {stranger}", dpop=None, method="GET", url=url) is None
        finally:
            await client.stop()

    asyncio.run(scenario())


def unstarted(fake: FakeKonklav, handle: Any = None) -> RelyingClient:
    """A client with room for one proof and one presentation, deciding through the check API."""
    http = httpx.AsyncClient(transport=httpx.MockTransport(handle or fake.handle))
    return RelyingClient(
        relying_url="http://konklav",
        subject_url="http://konklav",
        key_id="key",
        secret="secret",
        issuer=ISSUER,
        audience=AUDIENCE,
        http=http,
        dpop_replay_capacity=1,
    )


# With room for one presentation, one that stayed held would refuse the
# next request.
# r[verify item.py.accepted-request]
# r[verify relying.verify.accepted-presentation]
def test_presentations_the_check_api_refuses_or_fails_are_released() -> None:
    async def scenario() -> None:
        keys = Keys()
        key = DpopKey()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        failing = False

        async def handle(request: httpx.Request) -> httpx.Response:
            if failing and request.url.path == "/v1/check":
                return httpx.Response(500)
            return await fake.handle(request)

        client = unstarted(fake, handle)
        url = "https://api.example/projects/1"

        def headers(token: str) -> dict[str, str]:
            return {"authorization": f"DPoP {token}", "dpop": key.proof("GET", url, token), "method": "GET", "url": url}

        # The fake check API refuses tokens for another audience.
        other = keys.token(subject=subject, session=session, tenant=tenant, jkt=key.jkt(), audience="other")
        assert await client.accept_request(**headers(other)) is None
        token = keys.token(subject=subject, session=session, tenant=tenant, jkt=key.jkt())
        failing = True
        with pytest.raises(KonklavError):
            await client.accept_request(**headers(token))
        failing = False
        accepted = await client.accept_request(**headers(token))
        assert accepted is not None, "the earlier presentations are still held"
        # The accepted one is held until it is released.
        with pytest.raises(InvalidDpopProof):
            await client.accept_request(**headers(token))

    asyncio.run(scenario())


# r[verify relying.verify.dpop-replay]
# r[verify relying.verify.dpop-before-check]
def test_a_proof_the_check_api_decided_with_is_refused_again() -> None:
    async def scenario() -> None:
        keys = Keys()
        key = DpopKey()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        client = unstarted(fake)
        url = "https://api.example/projects/1"

        def headers(token: str) -> dict[str, str]:
            return {"authorization": f"DPoP {token}", "dpop": key.proof("GET", url, token), "method": "GET", "url": url}

        # A proof for a token the check API refuses takes none of the room.
        other = keys.token(subject=subject, session=session, tenant=tenant, jkt=key.jkt(), audience="other")
        refused = await client.decide_request(**headers(other), requirements={})
        assert refused == {"decision": "deny", "reason": "invalid_token"}
        assert await client.verify_request(**headers(other)) is None

        token = keys.token(subject=subject, session=session, tenant=tenant, jkt=key.jkt())
        once = headers(token)
        assert await client.decide_request(**once, requirements={}) == {"decision": "allow"}
        replayed = await client.decide_request(**once, requirements={})
        assert replayed == {"decision": "deny", "reason": "invalid_dpop_proof"}
        with pytest.raises(InvalidDpopProof):
            await client.verify_request(**once)
        with pytest.raises(InvalidDpopProof):
            await client.accept_request(**once)

    asyncio.run(scenario())


# r[verify item.py.http]
def test_requests_time_out_but_the_feed_only_when_silent() -> None:
    fake = FakeKonklav(Keys(), *(str(uuid.uuid4()) for _ in range(3)))
    client = RelyingClient(
        relying_url="http://konklav",
        subject_url="http://konklav",
        key_id="key",
        secret="secret",
        issuer=ISSUER,
        audience=AUDIENCE,
        heartbeat_ms=2_000,
    )
    assert client._http.timeout == httpx.Timeout(10.0)
    assert client._http.follow_redirects is False
    assert client._feed_timeout == httpx.Timeout(10.0, read=6.0)
    assert fake.calls == []


# r[verify item.py.accepted-request]
# r[verify relying.verify.route-authority]
def test_a_route_decision_vouches_for_its_requests_later_decisions() -> None:
    async def scenario() -> None:
        keys = Keys()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        fake.actions = ["user:manage_data"]
        fake.vouches = {"user:manage_data": ["user:write"]}
        client = client_for(fake)
        token = keys.token(subject=subject, session=session, tenant=tenant)
        url = "https://api.example/users/data"
        request = {"authorization": f"Bearer {token}", "dpop": None, "method": "GET", "url": url}
        manage = {"tenant": ["user:manage_data"]}
        write = {"tenant": ["user:write"]}
        denied = {"decision": "deny", "reason": {"missing_actions": {"actions": ["user:write"]}}}

        async def goal() -> None:
            direct = await client.accept_request(**request)
            assert direct is not None
            assert await client.decide_accepted(direct, write, route=True) == denied
            client.release_accepted(direct)

            accepted = await client.accept_request(**request)
            assert accepted is not None
            assert await client.decide_accepted(accepted, write) == denied, "no route decision yet"
            route = await client.decide_accepted_typed(accepted, manage, route=True)
            assert route.allowed
            assert await client.decide_accepted(accepted, write) == {"decision": "allow"}
            client.release_accepted(accepted)

        # Before the feed is up, through the check API: the route decision
        # is sent without route authority, later ones with what it vouched.
        await goal()
        sent = [check.get("route_authority") for check in fake.checks if check["requirements"] != {"token_kinds": ["partial", "identity", "tenant", "reset_password", "invite"]}]
        assert sent == [None, {}, None, {"tenant": ["user:write"]}]

        await client.start()
        try:
            await until_trusted(client)
            fake.checks.clear()
            await goal()
            assert fake.checks == [], "decided locally"
        finally:
            await client.stop()

    asyncio.run(scenario())


# r[verify item.py.typed.compatible]
# r[verify authz.decision.tenant-facts]
# r[verify relying.fallback.equivalence]
def test_typed_variants_decide_route_policies() -> None:
    async def scenario() -> None:
        keys = Keys()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        client = client_for(fake)
        token = keys.token(subject=subject, session=session, tenant=tenant)
        policy = Policy.merge(
            Policy(tenant_actions={"project:read"}),
            Policy(tenant_facts={"tenant_type": ["client"]}),
        )
        requirements = policy.requirements()

        # Through the check API, typed like the JSON.
        assert await client.decide_typed(token, requirements) == Decision("allow")
        assert await client.decide(token, requirements) == {"decision": "allow"}

        await client.start()
        try:
            await until_trusted(client)
            fake.calls.clear()
            assert (await client.decide_typed(token, requirements)).allowed
            assert "/v1/check" not in fake.calls, "decided locally"

            # The tenant stops matching.
            fake.tenant_facts = {"tenant_type": "personal"}
            fake.revision = 2
            cursor = fake.push("entitlements.changed", {"all": True, "tenant": tenant})
            assert await client.await_cursor(cursor)
            decision = Decision("allow")
            for _ in range(100):
                decision = await client.decide_typed(token, requirements)
                if not decision.allowed:
                    break
                await asyncio.sleep(0.02)
            assert decision == Decision("deny", reason=DenyReason("tenant_facts", fact="tenant_type"))
            assert await client.decide(token, requirements) == {
                "decision": "deny",
                "reason": {"tenant_facts": {"fact": "tenant_type"}},
            }

            verified = await client.verify_typed(token)
            assert isinstance(verified, AccessToken)
            assert (verified.sub, verified.tid, verified.sid) == (subject, tenant, session)
            assert await client.verify_typed("not.a.token") is None
            requested = await client.verify_request_typed(
                authorization=f"Bearer {token}", dpop=None, method="GET", url="https://api.example/p"
            )
            assert requested == verified
            assert (
                await client.decide_request_typed(
                    authorization=f"Bearer {token}",
                    dpop=None,
                    method="GET",
                    url="https://api.example/p",
                    requirements=requirements,
                )
            ) == decision
        finally:
            await client.stop()

    asyncio.run(scenario())


# r[verify relying.erasure.notify]
# r[verify relying.erasure.reset]
def test_erasures_reach_the_handler_and_the_list_catches_up() -> None:
    async def scenario() -> None:
        keys = Keys()
        subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
        fake = FakeKonklav(keys, subject, tenant, session)
        notices: asyncio.Queue[ErasureNotice] = asyncio.Queue()
        failing = True

        async def on_erasure(notice: ErasureNotice) -> None:
            await notices.put(notice)
            if failing:
                raise RuntimeError("the relying system's database is down")

        client = RelyingClient(
            relying_url="http://konklav",
            subject_url="http://konklav",
            key_id="key",
            secret="secret",
            issuer=ISSUER,
            audience=AUDIENCE,
            http=httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)),
            on_erasure=on_erasure,
            heartbeat_ms=500,
            debounce_ms=50,
        )
        token = keys.token(subject=subject, session=session, tenant=tenant)
        requirements = {"tenant": ["project:read"]}

        async def next_notice() -> ErasureNotice:
            return await asyncio.wait_for(notices.get(), timeout=5)

        await client.start()
        try:
            await until_trusted(client)
            # A stream starts by naming its position; a client with none of
            # its own can't know what it missed.
            fake.push("position", {})
            assert await next_notice() == ErasuresMissed(since=None)
            assert await client.decide(token, requirements) == {"decision": "allow"}

            # Konklav revokes the sessions, then reports the erasure. A
            # handler that fails doesn't stop the next notice.
            fake.session_revoked = True
            fake.session_version = 2
            fake.actions = []
            fake.push("session.changed", fake.session_state())
            cursor = fake.push("subject.erased", {"subject": subject, "erased_at": 1_800_000_000})
            assert await next_notice() == Erased(subject=subject, erased_at=1_800_000_000)
            assert await client.await_cursor(cursor)
            assert await client.decide(token, requirements) == {"decision": "deny", "reason": "invalid_token"}

            failing = False
            fake.push("reset", {})
            missed = await next_notice()
            assert isinstance(missed, ErasuresMissed)
            assert missed.since is not None

            # Catching up pages through the list.
            other = str(uuid.uuid4())
            fake.erased = [
                {"subject": subject, "erased_at": 1_800_000_000},
                {"subject": other, "erased_at": 1_800_000_050},
            ]
            assert await client.erased_subjects() == [
                Erased(subject=subject, erased_at=1_800_000_000),
                Erased(subject=other, erased_at=1_800_000_050),
            ]
            assert await client.erased_subjects(since=1_800_000_050) == [Erased(subject=other, erased_at=1_800_000_050)]
            assert await client.erased_subjects(since=1_900_000_000) == []
        finally:
            await client.stop()

    asyncio.run(scenario())


# httpx resolves dot segments, so the scope `document/..` was asked for at
# `/v1/registered-scopes/`.
# r[verify item.py.path-segments]
def test_scope_ids_never_retarget_the_request() -> None:
    async def scenario() -> None:
        asked: list[bytes] = []

        def konklav(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/login/secret-key":
                return httpx.Response(200, json={"access_token": "service", "expires_in": 900})
            asked.append(request.url.raw_path)
            return httpx.Response(404)

        client = RelyingClient(
            relying_url="http://konklav",
            subject_url="http://konklav",
            key_id="key",
            secret="secret",
            issuer=ISSUER,
            audience=AUDIENCE,
            http=httpx.AsyncClient(transport=httpx.MockTransport(konklav)),
        )
        for unnameable in ["", ".", ".."]:
            await client._fetch({"need": "registered_scope", "kind": "document", "id": unnameable})
            await client._fetch({"need": "registered_scope", "kind": unnameable, "id": "d-1"})
        assert asked == [], "not asked: the core takes them for unknown"
        await client._fetch({"need": "registered_scope", "kind": "document", "id": "a/b ..?"})
        assert asked == [b"/v1/registered-scopes/document/a%2Fb%20..%3F"]

    asyncio.run(scenario())
