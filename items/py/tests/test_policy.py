import ast
import doctest
import pathlib

import pytest

import konklav_relying
from konklav_relying import (
    AccessToken,
    Decision,
    DenyReason,
    MissingScopeId,
    Policy,
    PolicyError,
    StepUp,
)
from konklav_relying import policy as policy_module
from konklav_relying import results as results_module

PACKAGE = pathlib.Path(konklav_relying.__file__).parent
README = pathlib.Path(__file__).parent.parent / "README.md"


@pytest.mark.parametrize("module", [policy_module, results_module], ids=lambda m: m.__name__)
def test_doctests(module: object) -> None:
    failed, tried = doctest.testmod(module, optionflags=doctest.ELLIPSIS)
    assert tried > 0 and failed == 0


def test_readme_doctests() -> None:
    failed, tried = doctest.testfile(str(README), module_relative=False, optionflags=doctest.ELLIPSIS)
    assert tried > 0 and failed == 0


# r[verify item.py.policy.framework-free]
def test_the_policy_layer_imports_only_the_standard_library() -> None:
    for name in ("policy.py", "results.py"):
        tree = ast.parse((PACKAGE / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] in {"__future__", "collections", "dataclasses", "types", "typing", "konklav_relying"}, node.module
            elif isinstance(node, ast.Import):
                raise AssertionError(f"{name} imports {[a.name for a in node.names]}")


# r[verify item.py.policy.fields]
# r[verify relying.decision.requirements]
def test_a_policy_states_everything_a_decide_request_does() -> None:
    policy = Policy(
        global_actions={"sys:read"},
        tenant_actions={"tenant:read"},
        scope_actions={"workspace": {"workspace:read"}, "workspace_patient": {"patient:read"}},
        token_kinds={"tenant", "identity"},
        admit_flags={"personal_only"},
        require_flags={"device_bound"},
        step_up=StepUp(min_methods=2, allowed_methods={"pwd", "otp"}, max_age_seconds=300),
        tenant_facts={"tenant_type": ["client"], "tier": [2, 1, 2]},
    )
    assert policy.requirements({"workspace": "w-1", "workspace_patient": "p-1"}) == {
        "token_kinds": ["identity", "tenant"],
        "global": ["sys:read"],
        "tenant": ["tenant:read"],
        "scopes": [
            {"kind": "workspace", "id": "w-1", "actions": ["workspace:read"]},
            {"kind": "workspace_patient", "id": "p-1", "actions": ["patient:read"]},
        ],
        "admit_flags": ["personal_only"],
        "require_flags": ["device_bound"],
        "step_up": {"min_methods": 2, "allowed_methods": ["otp", "pwd"], "max_age_seconds": 300},
        "tenant_facts": {"tenant_type": ["client"], "tier": [1, 2]},
    }
    # Unconstrained fields are left out, so Konklav's defaults apply.
    assert Policy().requirements() == {}
    assert Policy(token_kinds=set()).requirements() == {"token_kinds": []}
    assert policy == Policy.merge(policy)
    assert hash(policy) == hash(Policy.merge(policy))
    with pytest.raises(TypeError):
        Policy(tenant_actions="tenant:read")


# r[verify item.py.policy.validation]
# r[verify authz.decision.tenant-facts.shape]
@pytest.mark.parametrize("values", [[], [1.5], [None], [["a"]]])
def test_unmatchable_tenant_facts_are_refused(values: list) -> None:
    with pytest.raises(PolicyError):
        Policy(tenant_facts={"tenant_type": values})


def test_tenant_fact_values_keep_their_type() -> None:
    # `True == 1` in Python, not in Konklav.
    policy = Policy(tenant_facts={"flag": [True, 1]})
    assert policy.requirements()["tenant_facts"] == {"flag": [True, 1]}
    with pytest.raises(PolicyError):
        Policy.merge(Policy(tenant_facts={"flag": [True]}), Policy(tenant_facts={"flag": [1]}))


# r[verify item.py.policy.merge]
def test_merging_accumulates_intersects_and_takes_the_strictest() -> None:
    outer = Policy(
        tenant_actions={"tenant:read"},
        scope_actions={"workspace": {"workspace:read"}},
        token_kinds={"identity", "tenant"},
        admit_flags={"personal_only", "kiosk"},
        require_flags={"device_bound"},
        step_up=StepUp(min_methods=1, allowed_methods={"pwd", "otp", "webauthn"}, max_age_seconds=3600),
        tenant_facts={"tenant_type": ["client", "clinic"]},
    )
    inner = Policy(
        global_actions={"sys:read"},
        tenant_actions={"tenant:write"},
        scope_actions={"workspace": {"workspace:write"}, "personal_patient": {"patient:read"}},
        token_kinds={"tenant"},
        admit_flags={"personal_only"},
        require_flags={"mfa"},
        step_up=StepUp(min_methods=2, allowed_methods={"otp", "webauthn"}, max_age_seconds=300),
        tenant_facts={"tenant_type": ["clinic", "personal"], "region": ["se"]},
    )
    merged = Policy.merge(outer, inner)
    assert merged == Policy(
        global_actions={"sys:read"},
        tenant_actions={"tenant:read", "tenant:write"},
        scope_actions={"workspace": {"workspace:read", "workspace:write"}, "personal_patient": {"patient:read"}},
        token_kinds={"tenant"},
        admit_flags={"personal_only"},
        require_flags={"device_bound", "mfa"},
        step_up=StepUp(min_methods=2, allowed_methods={"otp", "webauthn"}, max_age_seconds=300),
        tenant_facts={"tenant_type": ["clinic"], "region": ["se"]},
    )
    # `None` leaves a field to the others, in either order.
    assert Policy.merge(Policy(), outer, Policy()) == outer
    assert Policy.merge(Policy(step_up=StepUp(max_age_seconds=60)), Policy(step_up=StepUp(min_methods=2))).step_up == StepUp(
        min_methods=2, max_age_seconds=60
    )
    assert Policy.merge() == Policy()


# r[verify item.py.policy.merge-contradiction]
def test_contradicting_tenant_facts_are_found_when_merging() -> None:
    with pytest.raises(PolicyError, match="tenant_type"):
        Policy.merge(Policy(tenant_facts={"tenant_type": ["client"]}), Policy(tenant_facts={"tenant_type": ["personal"]}))


# r[verify item.py.policy.override]
def test_overrides_replace_only_the_fields_they_set() -> None:
    inherited = Policy(
        tenant_actions={"tenant:read"},
        token_kinds={"tenant"},
        step_up=StepUp(max_age_seconds=300),
    )
    relaxed = Policy.merge(inherited, Policy.override(token_kinds={"identity", "tenant"}, step_up=StepUp()))
    assert relaxed == Policy(tenant_actions={"tenant:read"}, token_kinds={"identity", "tenant"}, step_up=StepUp())
    assert not relaxed.is_override
    # Later layers merge on top of the override as usual.
    assert Policy.merge(relaxed, Policy(token_kinds={"identity"})).token_kinds == {"identity"}
    assert Policy.merge(inherited, Policy.override()) == inherited


# r[verify item.py.policy.public]
def test_public_policies() -> None:
    public = Policy.public()
    assert Policy.merge(public).is_public
    assert Policy.merge(Policy(), public, Policy()).is_public
    with pytest.raises(PolicyError):
        public.requirements()
    with pytest.raises(PolicyError):
        Policy.merge(public, Policy(tenant_actions={"a"}))
    with pytest.raises(PolicyError):
        Policy.merge(Policy(tenant_actions={"a"}), public)
    with pytest.raises(PolicyError):
        Policy(is_public=True, tenant_actions={"a"})
    with pytest.raises(PolicyError):
        Policy.override(public=True, tenant_actions={"a"})
    # An override constrains a public router's route again, and another
    # makes it public again.
    guarded = Policy.merge(public, Policy.override(tenant_actions={"a"}))
    assert not guarded.is_public and guarded.requirements() == {"tenant": ["a"]}
    assert Policy.merge(guarded, Policy.override(public=True)).is_public


# r[verify item.py.policy.requirements]
# r[verify item.py.policy.token-tenant]
def test_requirements_resolve_scope_ids_and_owners() -> None:
    policy = Policy(tenant_actions={"tenant:read"}, scope_actions={"workspace": {"read"}, "project": set()})
    assert policy.scope_kinds == {"workspace", "project"}
    with pytest.raises(MissingScopeId) as missing:
        policy.requirements({"workspace": "w-1"})
    assert missing.value.kind == "project"
    resolved = policy.requirements(
        {"workspace": "w-1", "project": "p-1", "unused": "x"},
        scope_tenants={"project": "t-other"},
    )
    assert resolved == {
        "tenant": ["tenant:read"],
        "scopes": [
            {"kind": "project", "id": "p-1", "actions": [], "tenant": "t-other"},
            {"kind": "workspace", "id": "w-1", "actions": ["read"]},
        ],
    }
    # Tenant actions never name a tenant: they are the token's.
    assert "tenant" not in resolved["scopes"][1]


# r[verify item.py.typed.decision]
def test_decisions_read_every_shape() -> None:
    allowed = Decision.from_json(
        {
            "decision": "allow",
            "obligations": [{"share": "s-1", "tenant": "t-1", "kind": "project", "id": "p-1", "attributes": {"until": "x"}}],
        }
    )
    assert allowed.allowed and allowed.obligations[0].attributes == {"until": "x"}
    assert Decision.from_json({"decision": "allow"}) == Decision("allow")
    reasons = {
        "invalid_token": DenyReason("invalid_token"),
        "no_tenant": DenyReason("no_tenant"),
    }
    for code, expected in reasons.items():
        assert Decision.from_json({"decision": "deny", "reason": code}).reason == expected
    for reason, expected in [
        ({"restricted_session": {"flag": "f"}}, DenyReason("restricted_session", flag="f")),
        ({"confined_session": {"flag": "f"}}, DenyReason("confined_session", flag="f")),
        ({"missing_flag": {"flag": "f"}}, DenyReason("missing_flag", flag="f")),
        ({"unknown_scope": {"kind": "k", "id": "i"}}, DenyReason("unknown_scope", kind="k", id="i")),
        ({"missing_actions": {"actions": ["a", "b"]}}, DenyReason("missing_actions", actions=frozenset({"a", "b"}))),
        ({"tenant_facts": {"fact": "tenant_type"}}, DenyReason("tenant_facts", fact="tenant_type")),
    ]:
        decision = Decision.from_json({"decision": "deny", "reason": reason})
        assert not decision.allowed
        assert decision.reason == expected
        assert decision.reason.details == next(iter(reason.values()))
    newer = Decision.from_json({"decision": "deny", "reason": {"from_the_future": {"x": 1}}})
    assert not newer.allowed and newer.reason.code == "from_the_future"
    step_up = Decision.from_json(
        {"decision": "step_up", "requirement": {"min_methods": 2, "allowed_methods": ["otp"], "max_age_seconds": 60}}
    )
    assert not step_up.allowed
    assert step_up.step_up == StepUp(min_methods=2, allowed_methods={"otp"}, max_age_seconds=60)
    with pytest.raises(ValueError):
        Decision.from_json({"decision": "maybe"})


# r[verify item.py.typed.access-token]
def test_access_tokens_read_every_claim() -> None:
    claims = {
        "iss": "https://auth.example",
        "aud": "api",
        "sub": "s-1",
        "jti": "j-1",
        "iat": 100,
        "exp": 1000,
        "knd": "tenant",
        "sid": "x-1",
        "cid": "c-1",
        "sv": 3,
        "amr": ["pwd", "otp"],
        "auth_time": 90,
        "tid": "t-1",
        "mid": "m-1",
        "sfl": ["personal_only"],
        "fct": {"tenant_type": "personal"},
        "act": {"sub": "s-0", "tid": "t-0"},
        "cnf": {"jkt": "thumb"},
    }
    token = AccessToken.from_claims(claims)
    assert (token.sub, token.knd, token.tid, token.mid, token.sid, token.sv, token.jti) == (
        "s-1", "tenant", "t-1", "m-1", "x-1", 3, "j-1",
    )
    assert (token.iat, token.exp, token.auth_time, token.amr, token.sfl) == (100, 1000, 90, ("pwd", "otp"), ("personal_only",))
    assert token.fct == {"tenant_type": "personal"}
    assert token.act is not None and (token.act.sub, token.act.tid) == ("s-0", "t-0")
    assert token.cid == "c-1" and token.cnf is not None and token.cnf.jkt == "thumb"
    identity = AccessToken.from_claims(
        {k: v for k, v in claims.items() if k not in {"tid", "mid", "sfl", "fct", "act", "cid", "cnf", "amr"}}
    )
    assert (identity.tid, identity.mid, identity.sfl, identity.fct, identity.act, identity.cnf) == (None, None, (), {}, None, None)
