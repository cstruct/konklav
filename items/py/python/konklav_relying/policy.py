"""
Route policies: an operation's requirements, declared once per route or
router, merged across the layers around it and resolved per request.

A `Policy` states everything a decide request expresses, with the ids of
the scopes it names left for the request to supply:

>>> read = Policy(tenant_actions={"project:read"}, scope_actions={"project": {"document:read"}})
>>> read.requirements({"project": "p-1"})
{'tenant': ['project:read'], 'scopes': [{'kind': 'project', 'id': 'p-1', 'actions': ['document:read']}]}

Policies declared on nested layers merge outermost first. Actions
accumulate, allowed sets intersect, the strictest step-up wins, and `None`
leaves a field to the other policies:

>>> router = Policy(
...     tenant_actions={"project:read"},
...     token_kinds={"identity", "tenant"},
...     step_up=StepUp(max_age_seconds=3600),
... )
>>> route = Policy(
...     tenant_actions={"project:write"},
...     token_kinds={"tenant"},
...     step_up=StepUp(min_methods=2, max_age_seconds=300),
...     tenant_facts={"tenant_type": ["client"]},
... )
>>> Policy.merge(router, route).requirements()
{'token_kinds': ['tenant'], 'tenant': ['project:read', 'project:write'], 'step_up': {'min_methods': 2, 'max_age_seconds': 300}, 'tenant_facts': {'tenant_type': ['client']}}

`Policy.override` replaces only the fields it sets, so a route can relax
what it inherits, and `Policy.public()` admits anyone:

>>> Policy.merge(router, Policy.override(step_up=StepUp())).requirements()
{'token_kinds': ['identity', 'tenant'], 'tenant': ['project:read']}
>>> Policy.merge(Policy.public()).is_public
True

Tenant actions, tenant facts and scopes without an owner tenant always mean
the token's tenant: a policy never names one. A host that takes a tenant
from the request, such as from a route's path, must deny when it isn't the
token's `tid` before deciding.

Nothing here decides: the requirements go to `RelyingClient.decide` (or
`decide_typed`), and the relying core decides them.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, ClassVar, NotRequired, Self, TypedDict, Unpack

__all__ = [
    "FactValue",
    "MissingScopeId",
    "Policy",
    "PolicyError",
    "PolicyFields",
    "Requirements",
    "ScopeRequirement",
    "StepUp",
    "StepUpRequirement",
]

type FactValue = str | int | bool
"""A value a tenant fact predicate can match."""


class PolicyError(ValueError):
    """A policy, or a merge of policies, that can't resolve to requirements."""


class MissingScopeId(PolicyError):
    """A scope kind the policy requires has no id among the request's."""

    def __init__(self, kind: str) -> None:
        super().__init__(f"no id for the required scope kind `{kind}`")
        self.kind = kind


class ScopeRequirement(TypedDict):
    """Actions required at one scope, as `decide` takes them."""

    tenant: NotRequired[str]
    kind: str
    id: str
    actions: list[str]


class StepUpRequirement(TypedDict, total=False):
    """A step-up requirement as `decide` takes it and decisions carry it."""

    min_methods: int
    allowed_methods: list[str]
    max_age_seconds: int


# `global` is a keyword, so the functional form.
Requirements = TypedDict(
    "Requirements",
    {
        "token_kinds": list[str],
        "global": list[str],
        "tenant": list[str],
        "scopes": list[ScopeRequirement],
        "admit_flags": list[str],
        "require_flags": list[str],
        "step_up": StepUpRequirement,
        "tenant_facts": dict[str, list[FactValue]],
    },
    total=False,
)
"""The requirements JSON that `decide` and `decide_request` take."""


def _strings(value: Iterable[str] | None, name: str) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        raise TypeError(f"{name} takes a set of strings, not a string")
    return frozenset(value)


def _fact_key(value: FactValue) -> tuple[str, FactValue]:
    # `True == 1` in Python, but not in JSON: keep the type.
    return (type(value).__name__, value)


def _fact_values(key: str, values: Iterable[FactValue]) -> tuple[FactValue, ...]:
    if isinstance(values, str):
        raise TypeError(f"tenant_facts takes a list of values for `{key}`, not a string")
    seen: dict[tuple[str, FactValue], FactValue] = {}
    for value in values:
        if not isinstance(value, str | int | bool):
            raise PolicyError(
                f"tenant_facts lists {value!r} for `{key}`: only strings, integers and booleans can be matched"
            )
        seen.setdefault(_fact_key(value), value)
    if not seen:
        raise PolicyError(f"tenant_facts lists no value for `{key}`")
    return tuple(value for _, value in sorted(seen.items(), key=lambda item: item[0]))


def _intersect_facts(key: str, a: tuple[FactValue, ...], b: tuple[FactValue, ...]) -> tuple[FactValue, ...]:
    allowed = {_fact_key(value) for value in b}
    both = tuple(value for value in a if _fact_key(value) in allowed)
    if not both:
        # r[impl item.py.policy.merge-contradiction]
        raise PolicyError(f"the merged policies allow no value of the tenant fact `{key}`")
    return both


def _combine[T](a: T | None, b: T | None, how: Any) -> T | None:
    if a is None:
        return b
    if b is None:
        return a
    return how(a, b)


def _min_none(a: int | None, b: int | None) -> int | None:
    return _combine(a, b, min)


def _max_none(a: int | None, b: int | None) -> int | None:
    return _combine(a, b, max)


@dataclass(frozen=True, kw_only=True)
class StepUp:
    """
    Stronger or fresher authentication an operation needs. `allowed_methods`
    are the `amr` methods that count towards `min_methods`; on their own
    they demand nothing.

    >>> StepUp(min_methods=1, max_age_seconds=600).merge(StepUp(min_methods=2, max_age_seconds=3600))
    StepUp(min_methods=2, allowed_methods=None, max_age_seconds=600)
    """

    min_methods: int | None = None
    allowed_methods: AbstractSet[str] | None = None
    max_age_seconds: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_methods", _strings(self.allowed_methods, "allowed_methods"))

    @property
    def is_empty(self) -> bool:
        return self.min_methods is None and self.allowed_methods is None and self.max_age_seconds is None

    def merge(self, other: StepUp) -> StepUp:
        """The stricter of both: more methods, from fewer allowed, more recently."""
        return StepUp(
            min_methods=_max_none(self.min_methods, other.min_methods),
            allowed_methods=_combine(self.allowed_methods, other.allowed_methods, frozenset.intersection),
            max_age_seconds=_min_none(self.max_age_seconds, other.max_age_seconds),
        )

    def to_json(self) -> StepUpRequirement:
        out: StepUpRequirement = {}
        if self.min_methods is not None:
            out["min_methods"] = self.min_methods
        if self.allowed_methods is not None:
            out["allowed_methods"] = sorted(self.allowed_methods)
        if self.max_age_seconds is not None:
            out["max_age_seconds"] = self.max_age_seconds
        return out

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> StepUp:
        allowed = data.get("allowed_methods")
        return cls(
            min_methods=data.get("min_methods"),
            allowed_methods=None if allowed is None else frozenset(allowed),
            max_age_seconds=data.get("max_age_seconds"),
        )


class PolicyFields(TypedDict, total=False):
    """The fields `Policy.override` can set."""

    global_actions: AbstractSet[str]
    tenant_actions: AbstractSet[str]
    scope_actions: Mapping[str, AbstractSet[str]]
    token_kinds: AbstractSet[str]
    admit_flags: AbstractSet[str]
    require_flags: AbstractSet[str]
    step_up: StepUp
    tenant_facts: Mapping[str, Iterable[FactValue]]


# r[impl item.py.policy.framework-free]
# r[impl item.py.policy.fields]
@dataclass(frozen=True, kw_only=True)
class Policy:
    """
    An operation's requirements with scope ids unresolved. Every field left
    `None` leaves its part unconstrained, so Konklav's default applies:
    only `tenant` tokens, no restrictive flag admitted.
    """

    CONSTRAINTS: ClassVar[tuple[str, ...]] = (
        "global_actions",
        "tenant_actions",
        "scope_actions",
        "token_kinds",
        "admit_flags",
        "require_flags",
        "step_up",
        "tenant_facts",
    )

    global_actions: AbstractSet[str] | None = None
    """Actions required globally, whatever the tenant."""
    tenant_actions: AbstractSet[str] | None = None
    """Actions required tenant-wide in the token's tenant."""
    scope_actions: Mapping[str, AbstractSet[str]] | None = None
    """Actions required per scope kind; the ids come with each request."""
    token_kinds: AbstractSet[str] | None = None
    """Accepted token kinds, such as `tenant` and `identity`."""
    admit_flags: AbstractSet[str] | None = None
    """Restrictive session flags the operation tolerates."""
    require_flags: AbstractSet[str] | None = None
    """Assertive session flags the operation needs."""
    step_up: StepUp | None = None
    tenant_facts: Mapping[str, Iterable[FactValue]] | None = None
    """Tenant fact keys, each with the values the token's tenant may have."""
    is_public: bool = False
    """Admits anyone without a token; see `Policy.public`."""
    is_override: bool = False
    """Replaces the fields it sets when merged; see `Policy.override`."""

    def __post_init__(self) -> None:
        for name in ("global_actions", "tenant_actions", "token_kinds", "admit_flags", "require_flags"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        if self.scope_actions is not None:
            scopes = {kind: _strings(actions, "scope_actions") for kind, actions in self.scope_actions.items()}
            object.__setattr__(self, "scope_actions", MappingProxyType(dict(sorted(scopes.items()))))
        if self.tenant_facts is not None:
            # r[impl item.py.policy.validation]
            facts = {key: _fact_values(key, values) for key, values in self.tenant_facts.items()}
            object.__setattr__(self, "tenant_facts", MappingProxyType(dict(sorted(facts.items()))))
        if self.is_public and self.constrains:
            raise PolicyError("a public policy can't also constrain")

    def __hash__(self) -> int:
        return hash(
            tuple(
                tuple(sorted(value.items())) if isinstance(value, Mapping) else value
                for value in (getattr(self, name) for name in (*self.CONSTRAINTS, "is_public", "is_override"))
            )
        )

    @property
    def constrains(self) -> bool:
        """Whether any constraint is set."""
        return any(getattr(self, name) is not None for name in self.CONSTRAINTS)

    @property
    def scope_kinds(self) -> frozenset[str]:
        """The scope kinds a request must supply ids for."""
        return frozenset(self.scope_actions or ())

    # r[impl item.py.policy.public]
    @classmethod
    def public(cls) -> Self:
        """
        Admits anyone, without a token. It can't be merged with constraints,
        only replaced by an override.
        """
        return cls(is_public=True)

    # r[impl item.py.policy.override]
    @classmethod
    def override(cls, *, public: bool = False, **fields: Unpack[PolicyFields]) -> Self:
        """
        Replaces, when merged, the values of the fields it sets, keeping the
        others. `public=True` makes the merged policy public instead.

        >>> base = Policy(tenant_actions={"a"}, admit_flags={"personal_only"})
        >>> Policy.merge(base, Policy.override(admit_flags=set())).admit_flags
        frozenset()
        >>> Policy.merge(base, Policy.override(admit_flags=set())).tenant_actions
        frozenset({'a'})
        """
        if public and fields:
            raise PolicyError("a public override sets no other field")
        return cls(is_override=True, is_public=public, **fields)

    # r[impl item.py.policy.merge]
    @classmethod
    def merge(cls, *policies: Policy) -> Policy:
        """
        One policy from those declared on nested layers, outermost first.

        >>> Policy.merge(
        ...     Policy(admit_flags={"personal_only", "kiosk"}, tenant_facts={"tier": [1, 2]}),
        ...     Policy(admit_flags={"personal_only"}, tenant_facts={"tier": [2, 3], "region": ["se"]}),
        ... ).requirements()
        {'admit_flags': ['personal_only'], 'tenant_facts': {'region': ['se'], 'tier': [2]}}
        >>> Policy.merge(Policy.public(), Policy(tenant_actions={"a"}))
        Traceback (most recent call last):
        ...
        konklav_relying.policy.PolicyError: a public policy can't be merged with constraints; override it instead
        """
        merged = Policy()
        for policy in policies:
            if policy.is_override and policy.is_public:
                merged = Policy.public()
            elif policy.is_override:
                changes = {name: getattr(policy, name) for name in cls.CONSTRAINTS if getattr(policy, name) is not None}
                if changes:
                    merged = replace(merged, is_public=False, **changes)
            else:
                merged = _merge_two(merged, policy)
        return merged

    # r[impl item.py.policy.requirements]
    # r[impl item.py.policy.token-tenant]
    def requirements(
        self,
        scope_ids: Mapping[str, str] | None = None,
        *,
        scope_tenants: Mapping[str, str] | None = None,
    ) -> Requirements:
        """
        The requirements JSON for one request, with each required scope
        kind's id from `scope_ids` and, when it is another tenant's scope,
        its owner tenant from `scope_tenants` (then only shares satisfy it).

        >>> Policy(scope_actions={"workspace": {"read"}}).requirements({})
        Traceback (most recent call last):
        ...
        konklav_relying.policy.MissingScopeId: no id for the required scope kind `workspace`
        """
        if self.is_public:
            raise PolicyError("a public policy needs no decision")
        ids = scope_ids or {}
        owners = scope_tenants or {}
        out: Requirements = {}
        if self.token_kinds is not None:
            out["token_kinds"] = sorted(self.token_kinds)
        if self.global_actions:
            out["global"] = sorted(self.global_actions)
        if self.tenant_actions:
            out["tenant"] = sorted(self.tenant_actions)
        if self.scope_actions:
            scopes: list[ScopeRequirement] = []
            for kind, actions in self.scope_actions.items():
                scope_id = ids.get(kind)
                if scope_id is None:
                    raise MissingScopeId(kind)
                scope: ScopeRequirement = {"kind": kind, "id": scope_id, "actions": sorted(actions)}
                if (owner := owners.get(kind)) is not None:
                    scope = {"tenant": owner, **scope}
                scopes.append(scope)
            out["scopes"] = scopes
        if self.admit_flags:
            out["admit_flags"] = sorted(self.admit_flags)
        if self.require_flags:
            out["require_flags"] = sorted(self.require_flags)
        if self.step_up is not None and not self.step_up.is_empty:
            out["step_up"] = self.step_up.to_json()
        if self.tenant_facts:
            out["tenant_facts"] = {key: list(values) for key, values in self.tenant_facts.items()}
        return out


def _merge_two(a: Policy, b: Policy) -> Policy:
    if a.is_public or b.is_public:
        if a.constrains or b.constrains:
            raise PolicyError("a public policy can't be merged with constraints; override it instead")
        return Policy.public()

    def scopes(x: Mapping[str, frozenset[str]], y: Mapping[str, frozenset[str]]) -> dict[str, frozenset[str]]:
        return {kind: x.get(kind, frozenset()) | y.get(kind, frozenset()) for kind in {*x, *y}}

    def facts(
        x: Mapping[str, tuple[FactValue, ...]], y: Mapping[str, tuple[FactValue, ...]]
    ) -> dict[str, tuple[FactValue, ...]]:
        return {
            key: _intersect_facts(key, x[key], y[key]) if key in x and key in y else x.get(key) or y[key]
            for key in {*x, *y}
        }

    return Policy(
        global_actions=_combine(a.global_actions, b.global_actions, frozenset.union),
        tenant_actions=_combine(a.tenant_actions, b.tenant_actions, frozenset.union),
        scope_actions=_combine(a.scope_actions, b.scope_actions, scopes),
        token_kinds=_combine(a.token_kinds, b.token_kinds, frozenset.intersection),
        admit_flags=_combine(a.admit_flags, b.admit_flags, frozenset.intersection),
        require_flags=_combine(a.require_flags, b.require_flags, frozenset.union),
        step_up=_combine(a.step_up, b.step_up, StepUp.merge),
        tenant_facts=_combine(a.tenant_facts, b.tenant_facts, facts),
    )
