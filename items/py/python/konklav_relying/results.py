"""
Typed results: decisions and access-token claims read from the JSON the
relying core and Konklav return.

>>> decision = Decision.from_json({"decision": "deny", "reason": {"tenant_facts": {"fact": "tenant_type"}}})
>>> decision.allowed, decision.reason.code, decision.reason.fact
(False, 'tenant_facts', 'tenant_type')
>>> Decision.from_json({"decision": "step_up", "requirement": {"min_methods": 2}}).step_up
StepUp(min_methods=2, allowed_methods=None, max_age_seconds=None)
>>> Decision.from_json({"decision": "deny", "reason": "invalid_token"}).reason
DenyReason(code='invalid_token', flag=None, kind=None, id=None, actions=frozenset(), fact=None)
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from konklav_relying.policy import StepUp

__all__ = [
    "AccessToken",
    "Actor",
    "Confirmation",
    "Decision",
    "DenyCode",
    "DenyReason",
    "Obligation",
]

type DenyCode = Literal[
    "invalid_token",
    "invalid_dpop_proof",
    "token_kind",
    "restricted_session",
    "confined_session",
    "tenant_facts",
    "missing_flag",
    "no_tenant",
    "unknown_scope",
    "missing_actions",
]
"""The deny reasons Konklav gives; `DenyReason.code` may hold others from a newer server."""


def _frozen(mapping: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return MappingProxyType(dict(mapping or {}))


@dataclass(frozen=True)
class DenyReason:
    """
    Why a decision denies: `code`, and the fields that reason carries
    (`flag` for `restricted_session`, `confined_session` and `missing_flag`,
    `kind` and `id` for `unknown_scope`, `actions` for `missing_actions`,
    `fact` for `tenant_facts`).
    """

    code: DenyCode | str
    flag: str | None = None
    kind: str | None = None
    id: str | None = None
    actions: frozenset[str] = frozenset()
    fact: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)
    """The reason's fields as Konklav sent them."""

    @classmethod
    def from_json(cls, data: str | Mapping[str, Any]) -> DenyReason:
        if isinstance(data, str):
            return cls(code=data)
        if len(data) != 1:
            raise ValueError(f"not a deny reason: {data!r}")
        ((code, details),) = data.items()
        details = details if isinstance(details, Mapping) else {}
        return cls(
            code=code,
            flag=details.get("flag"),
            kind=details.get("kind"),
            id=details.get("id"),
            actions=frozenset(details.get("actions") or ()),
            fact=details.get("fact"),
            details=_frozen(details),
        )


@dataclass(frozen=True)
class Obligation:
    """A share's attributes, for the relying system to apply to an allowed operation."""

    share: str
    tenant: str
    """The owner tenant of the shared scope."""
    kind: str
    id: str
    attributes: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Obligation:
        return cls(
            share=data["share"],
            tenant=data["tenant"],
            kind=data["kind"],
            id=data["id"],
            attributes=_frozen(data.get("attributes")),
        )


# r[impl item.py.typed.decision]
@dataclass(frozen=True)
class Decision:
    """
    A decision: `allow` with the obligations of the shares it relied on,
    `deny` with its `reason`, or `step_up` with the authentication that
    could still succeed in `step_up`.
    """

    decision: Literal["allow", "deny", "step_up"]
    reason: DenyReason | None = None
    step_up: StepUp | None = None
    obligations: tuple[Obligation, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Decision:
        """Reads a decision; raises `ValueError` for anything else, so nothing unknown allows."""
        match data.get("decision"):
            case "allow":
                return cls("allow", obligations=tuple(Obligation.from_json(o) for o in data.get("obligations", ())))
            case "deny":
                return cls("deny", reason=DenyReason.from_json(data["reason"]))
            case "step_up":
                return cls("step_up", step_up=StepUp.from_json(data.get("requirement") or {}))
            case other:
                raise ValueError(f"not a decision: {other!r}")


@dataclass(frozen=True)
class Actor:
    """The `act` claim: who really acts behind an impersonated session."""

    sub: str
    tid: str | None = None


@dataclass(frozen=True)
class Confirmation:
    """The `cnf` claim of a sender-constrained token."""

    jkt: str
    """The RFC 7638 thumbprint of the session's DPoP key."""


# r[impl item.py.typed.access-token]
@dataclass(frozen=True)
class AccessToken:
    """
    The claims of a verified access token. Ids are strings, times Unix
    seconds.

    >>> token = AccessToken.from_claims({
    ...     "iss": "https://auth.example", "aud": "api", "sub": "s-1", "jti": "j", "iat": 1, "exp": 901,
    ...     "knd": "tenant", "sid": "x-1", "sv": 1, "amr": ["pwd"], "auth_time": 1, "tid": "t-1",
    ...     "sfl": ["personal_only"], "fct": {"tenant_type": "personal"},
    ... })
    >>> token.tid, token.sfl, token.fct["tenant_type"], token.cnf
    ('t-1', ('personal_only',), 'personal', None)
    """

    iss: str
    aud: str
    sub: str
    """The subject."""
    knd: str
    """The token kind: `partial`, `identity`, `tenant`, `reset_password` or `invite`."""
    sid: str
    """The session."""
    sv: int
    """The session version the token was issued at."""
    jti: str
    iat: int
    exp: int
    auth_time: int
    amr: tuple[str, ...] = ()
    tid: str | None = None
    """The tenant the token targets."""
    mid: str | None = None
    """The membership in that tenant."""
    sfl: tuple[str, ...] = ()
    """Session flags."""
    fct: Mapping[str, Any] = field(default_factory=dict)
    """Portable facts, as of issuance."""
    act: Actor | None = None
    cid: str | None = None
    """The credential the session was established with."""
    cnf: Confirmation | None = None

    @classmethod
    def from_claims(cls, claims: Mapping[str, Any]) -> AccessToken:
        act = claims.get("act")
        cnf = claims.get("cnf")
        return cls(
            iss=claims["iss"],
            aud=claims["aud"],
            sub=claims["sub"],
            knd=claims["knd"],
            sid=claims["sid"],
            sv=claims["sv"],
            jti=claims["jti"],
            iat=claims["iat"],
            exp=claims["exp"],
            auth_time=claims["auth_time"],
            amr=tuple(claims.get("amr", ())),
            tid=claims.get("tid"),
            mid=claims.get("mid"),
            sfl=tuple(claims.get("sfl", ())),
            fct=_frozen(claims.get("fct")),
            act=None if act is None else Actor(sub=act["sub"], tid=act.get("tid")),
            cid=claims.get("cid"),
            cnf=None if cnf is None else Confirmation(jkt=cnf["jkt"]),
        )
