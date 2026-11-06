import json
import time
import uuid

from konklav_relying import Core
from support import AUDIENCE, ISSUER, DpopKey, Keys


def now() -> int:
    return time.time_ns() // 1_000_000


def warm_core(keys: Keys, subject: str, tenant: str, session: str) -> Core:
    core = Core(json.dumps({"issuer": ISSUER, "audience": AUDIENCE}))
    core.on_feed_connected(now())
    core.on_jwks(json.dumps(keys.jwks()), now())
    core.on_session(
        json.dumps(
            {"session": session, "subject": subject, "version": 1, "revoked": False, "expires_at": int(time.time()) + 3600}
        )
    )
    core.on_entitlements(
        json.dumps(
            {
                "subject_id": subject,
                "tenant_id": tenant,
                "revision": 1,
                "global": [],
                "tenant": ["project:read"],
                "scoped": [],
                "restrictive_flags": ["personal_only"],
                "confinements": {"tenant_facts": {"tenant_type": "client"}},
            }
        ),
        now(),
    )
    return core


def decide(core: Core, token: str, requirements: dict) -> dict:
    return json.loads(core.decide(token, json.dumps(requirements), now()))


def test_decides_locally_and_applies_revocations_immediately() -> None:
    keys = Keys()
    subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
    core = warm_core(keys, subject, tenant, session)
    token = keys.token(subject=subject, session=session, tenant=tenant)
    assert decide(core, token, {"tenant": ["project:read"]}) == {"outcome": "decided", "decision": {"decision": "allow"}}
    missing = decide(core, token, {"tenant": ["document:write"]})
    assert missing["decision"]["reason"] == {"missing_actions": {"actions": ["document:write"]}}

    revoked = {"session": session, "subject": subject, "version": 2, "revoked": True, "expires_at": int(time.time()) + 3600}
    core.on_feed_event(json.dumps({"cursor": 5, "kind": "session.changed", "payload": revoked}), now())
    assert decide(core, token, {"tenant": ["project:read"]})["decision"] == {"decision": "deny", "reason": "invalid_token"}
    assert core.feed_cursor() == 5


def test_restrictive_flags_need_admitting() -> None:
    keys = Keys()
    subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
    core = warm_core(keys, subject, tenant, session)
    token = keys.token(subject=subject, session=session, tenant=tenant, flags=["personal_only"])
    denied = decide(core, token, {"tenant": ["project:read"]})
    assert denied["decision"]["reason"] == {"restricted_session": {"flag": "personal_only"}}
    admitted = decide(core, token, {"tenant": ["project:read"], "admit_flags": ["personal_only"]})
    assert admitted["decision"] == {"decision": "allow"}


def test_untrusted_caches_ask_for_the_check_api() -> None:
    core = Core(json.dumps({"issuer": ISSUER, "audience": AUDIENCE}))
    outcome = decide(core, "any.token.here", {})
    assert outcome == {"outcome": "need", "needs": [{"need": "check"}]}


def test_rejects_malformed_input() -> None:
    core = Core(json.dumps({"issuer": ISSUER, "audience": AUDIENCE}))
    for call in (
        lambda: core.on_feed_event(json.dumps({"cursor": 1, "kind": "session.changed", "payload": {}}), now()),
        lambda: core.decide("t", "not json", now()),
        lambda: Core("{"),
    ):
        try:
            call()
        except ValueError:
            continue
        raise AssertionError("expected ValueError")


def presented(authorization: str, dpop: str | None, url: str = "https://api.example/projects/1") -> str:
    return json.dumps({"authorization": authorization, "dpop": dpop, "request": {"method": "GET", "url": url}})


def test_sender_constrained_tokens_need_their_proof() -> None:
    keys = Keys()
    key = DpopKey()
    subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
    core = warm_core(keys, subject, tenant, session)
    token = keys.token(subject=subject, session=session, tenant=tenant, jkt=key.jkt())
    requirements = json.dumps({"tenant": ["project:read"]})
    proof = key.proof("GET", "https://api.example/projects/1", token)

    allowed = json.loads(core.decide_presented(presented(f"DPoP {token}", proof), requirements, now()))
    assert allowed["decision"] == {"decision": "allow"}
    refused = {"decision": "deny", "reason": "invalid_dpop_proof"}
    replayed = json.loads(core.decide_presented(presented(f"DPoP {token}", proof), requirements, now()))
    assert replayed["decision"] == refused
    assert decide(core, token, {"tenant": ["project:read"]})["decision"] == refused
    assert json.loads(core.verify_presented(presented(f"Bearer {token}", None), now())) == {"outcome": "invalid_proof"}


# r[verify authz.decision.tenant-facts]
# r[verify authz.decision.tenant-facts.shape]
def test_tenant_facts_are_decided_from_the_cached_set() -> None:
    keys = Keys()
    subject, tenant, session = (str(uuid.uuid4()) for _ in range(3))
    core = warm_core(keys, subject, tenant, session)
    token = keys.token(subject=subject, session=session, tenant=tenant)
    assert decide(core, token, {"tenant_facts": {"tenant_type": ["client"]}})["decision"] == {"decision": "allow"}
    assert decide(core, token, {"tenant_facts": {"tenant_type": ["personal"]}})["decision"] == {
        "decision": "deny",
        "reason": {"tenant_facts": {"fact": "tenant_type"}},
    }
    for unmatchable in ([], [1.5], [None]):
        try:
            decide(core, token, {"tenant_facts": {"tenant_type": unmatchable}})
        except ValueError:
            continue
        raise AssertionError(f"{unmatchable} should be refused")
