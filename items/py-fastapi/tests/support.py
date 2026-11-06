"""Helpers: a relying client that records what it is asked, and tokens it can read."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from konklav_relying import AcceptedRequest, AccessToken, Decision, InvalidDpopProof, KonklavError


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token(*, kind: str = "tenant", tenant: str | None = "t-1", **claims: Any) -> str:
    """A token whose claims read; FakeClient's decisions stand in for its signature."""
    now = int(time.time())
    payload = {
        "iss": "https://auth.example",
        "aud": "api",
        "sub": "s-1",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 900,
        "knd": kind,
        "sid": "x-1",
        "sv": 1,
        "amr": ["pwd"],
        "auth_time": now,
        **({"tid": tenant} if tenant is not None else {}),
        **claims,
    }
    return f"{b64(b'{}')}.{b64(json.dumps(payload).encode())}.c2ln"


def claims_of(raw: str) -> dict[str, Any] | None:
    try:
        payload = raw.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return None
    return claims if isinstance(claims, dict) else None


@dataclass
class FakeClient:
    """
    Stands in for a started `RelyingClient`: accepts tokens whose claims
    read, except `invalid`, `unreachable` and `bad-proof`, and decides with
    `decide`.
    """

    decide: Callable[[dict[str, Any]], dict[str, Any] | Exception] = lambda _: {"decision": "allow"}
    accepted: list[dict[str, Any]] = field(default_factory=list)
    decided: list[dict[str, Any]] = field(default_factory=list)
    verified: list[dict[str, Any]] = field(default_factory=list)

    def _token(self, request: dict[str, Any]) -> AccessToken | None:
        raw = request["authorization"].partition(" ")[2]
        if raw == "unreachable":
            raise KonklavError("down")
        if raw == "bad-proof":
            raise InvalidDpopProof("bad")
        claims = claims_of(raw)
        return None if claims is None else AccessToken.from_claims(claims)

    async def accept_request(self, **request: Any) -> AcceptedRequest | None:
        self.accepted.append(request)
        token = self._token(request)
        if token is None:
            return None
        return AcceptedRequest(token=token, presentation=str(len(self.accepted) - 1), access_token="")

    async def decide_accepted_typed(self, accepted: AcceptedRequest, requirements: dict[str, Any]) -> Decision:
        request = {**self.accepted[int(accepted.presentation)], "requirements": requirements}
        self.decided.append(request)
        outcome = self.decide(request)
        if isinstance(outcome, Exception):
            raise outcome
        return Decision.from_json(outcome)

    async def verify_request_typed(self, **request: Any) -> AccessToken | None:
        self.verified.append(request)
        return self._token(request)


class DpopKey:
    """A client's P-256 DPoP key, signing proofs (RFC 9449)."""

    def __init__(self) -> None:
        self.private = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.x = b64(numbers.x.to_bytes(32, "big"))
        self.y = b64(numbers.y.to_bytes(32, "big"))

    def proof(self, method: str, url: str, token: str | None = None) -> str:
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": {"kty": "EC", "crv": "P-256", "x": self.x, "y": self.y}}
        claims: dict[str, Any] = {"jti": str(uuid.uuid4()), "htm": method, "htu": url, "iat": int(time.time())}
        if token is not None:
            claims["ath"] = b64(hashlib.sha256(token.encode()).digest())
        signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
        r, s = decode_dss_signature(self.private.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        return f"{signing_input}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
