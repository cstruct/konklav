"""Helpers the example's Python services share."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# The browser files both versions of the example share (`examples/sso-compose/web`).
WEB_ROOT = Path("/app/web")
WEB = WEB_ROOT / "shared"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def secrets() -> dict[str, str]:
    """What the setup service wrote for the apps."""
    return json.loads(Path(os.environ["SECRETS_FILE"]).read_text())


def split_key(key: str) -> tuple[str, str]:
    """A secret key's `<key id>.<secret>`, as the relying client takes it."""
    key_id, _, secret = key.partition(".")
    return key_id, secret


def claims_of(jwt: str) -> dict[str, Any]:
    """A JWT's claims, *without verifying it*. Only for tokens just received
    from Konklav's token endpoint, or after the relying client verified it."""
    payload = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


class DpopKey:
    """A P-256 key for DPoP proofs (RFC 9449), held in this process only."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        numbers = self._key.public_key().public_numbers()
        self.jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big")),
        }

    def thumbprint(self) -> str:
        """The `jkt` (RFC 7638): the required members, sorted, no whitespace."""
        members = {name: self.jwk[name] for name in ("crv", "kty", "x", "y")}
        canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
        return b64url(hashlib.sha256(canonical.encode()).digest())

    def proof(self, method: str, url: str, access_token: str | None = None) -> str:
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk}
        claims: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": url,
            "iat": int(time.time()),
        }
        if access_token:
            claims["ath"] = b64url(hashlib.sha256(access_token.encode()).digest())
        signing_input = ".".join(
            b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
        )
        der = self._key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        # JWS wants the raw r || s, not DER.
        r, s = decode_dss_signature(der)
        return f"{signing_input}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def security_headers(csp: str) -> dict[str, str]:
    """Headers for the example's pages. A strict CSP matters most here: a
    page whose tokens live in memory is only as safe as its scripts."""
    return {
        "content-security-policy": csp,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "x-frame-options": "DENY",
        "cache-control": "no-store",
    }
