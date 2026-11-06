import asyncio
import uuid

import httpx
import pytest

from konklav_relying import AccessToken, Decision, DenyReason, InvalidDpopProof, Policy, RelyingClient
from support import AUDIENCE, ISSUER, DpopKey, FakeKonklav, Keys


def client_for(fake: FakeKonklav) -> RelyingClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake.handle))
    return RelyingClient(
        relying_url="http://konklav",
        subject_url="http://konklav",
        key_id="key",
        secret="secret",
        issuer=ISSUER,
        audience=AUDIENCE,
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
            # Once decided, neither the presentation nor its proof works again.
            assert await client.decide_accepted(accepted, reading) == {"decision": "deny", "reason": "invalid_token"}
            with pytest.raises(InvalidDpopProof):
                await client.accept_request(**once)
            stranger = Keys().token(subject=subject, session=session, tenant=tenant)
            assert await client.accept_request(authorization=f"Bearer {stranger}", dpop=None, method="GET", url=url) is None
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
