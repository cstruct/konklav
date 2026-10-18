import asyncio
import uuid

import httpx

from konklav_relying import RelyingClient
from support import AUDIENCE, ISSUER, FakeKonklav, Keys


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
        requirements = {"tenant": ["workspace:read"]}

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
            assert decision["reason"] == {"missing_actions": {"actions": ["workspace:read"]}}

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
            assert entitlements["tenant"] == ["workspace:read"]
        finally:
            await client.stop()

    asyncio.run(scenario())
