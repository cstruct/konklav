"""Helpers: Ed25519-signed tokens and a fake Konklav on httpx.MockTransport."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
import uuid
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ISSUER = "https://auth.example"
AUDIENCE = "api"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Keys:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.kid = b64(hashlib.sha256(self.public).digest())

    def jwks(self) -> dict[str, Any]:
        return {
            "keys": [
                {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": self.kid, "x": b64(self.public)}
            ]
        }

    def token(
        self,
        *,
        subject: str,
        session: str,
        tenant: str,
        version: int = 1,
        flags: list[str] | None = None,
        jkt: str | None = None,
    ) -> str:
        now = int(time.time())
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self.kid}
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": subject,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 900,
            "knd": "tenant",
            "sid": session,
            "sv": version,
            "amr": ["pwd"],
            "auth_time": now,
            "tid": tenant,
            "sfl": flags or [],
        }
        if jkt is not None:
            claims["cnf"] = {"jkt": jkt}
        signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
        signature = self.private.sign(signing_input.encode())
        return f"{signing_input}.{b64(signature)}"


class DpopKey:
    """A client's P-256 DPoP key, signing proofs (RFC 9449)."""

    def __init__(self) -> None:
        self.private = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.x = b64(numbers.x.to_bytes(32, "big"))
        self.y = b64(numbers.y.to_bytes(32, "big"))

    def jkt(self) -> str:
        canonical = json.dumps({"crv": "P-256", "kty": "EC", "x": self.x, "y": self.y}, separators=(",", ":"))
        return b64(hashlib.sha256(canonical.encode()).digest())

    def proof(self, method: str, url: str, token: str) -> str:
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": {"kty": "EC", "crv": "P-256", "x": self.x, "y": self.y}}
        claims = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": url,
            "iat": int(time.time()),
            "ath": b64(hashlib.sha256(token.encode()).digest()),
        }
        signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
        r, s = decode_dss_signature(self.private.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        return f"{signing_input}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class FakeKonklav:
    """Serves the relying surface from in-memory state; feed events are pushed."""

    def __init__(self, keys: Keys, subject: str, tenant: str, session: str) -> None:
        self.keys = keys
        self.subject = subject
        self.tenant = tenant
        self.session = session
        self.actions = ["project:read"]
        self.revision = 1
        self.session_version = 1
        self.session_revoked = False
        self.events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.cursor = 0
        self.calls: list[str] = []

    def push(self, kind: str, payload: dict[str, Any]) -> int:
        self.cursor += 1
        self.events.put_nowait({"cursor": self.cursor, "kind": kind, "payload": payload})
        return self.cursor

    def session_state(self) -> dict[str, Any]:
        return {
            "session": self.session,
            "subject": self.subject,
            "version": self.session_version,
            "revoked": self.session_revoked,
            "expires_at": int(time.time()) + 3600,
        }

    async def _feed(self):
        yield b": connected\n\n"
        while True:
            try:
                event = await asyncio.wait_for(self.events.get(), timeout=0.5)
            except TimeoutError:
                yield b":heartbeat\n\n"
                continue
            yield f"id: {event['cursor']}\nevent: {event['kind']}\ndata: {json.dumps(event)}\n\n".encode()

    async def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        if path == "/v1/login/secret-key":
            return httpx.Response(200, json={"access_token": "service", "expires_in": 900})
        if path == "/.well-known/jwks.json":
            return httpx.Response(200, json=self.keys.jwks())
        if path.startswith("/v1/session-states/"):
            if path.rsplit("/", 1)[1] != self.session:
                return httpx.Response(404, json={"error": {"code": "NOT_FOUND", "message": "x"}})
            return httpx.Response(200, json=self.session_state())
        if path.startswith("/v1/entitlements/"):
            return httpx.Response(
                200,
                json={
                    "subject_id": self.subject,
                    "tenant_id": self.tenant,
                    "revision": self.revision,
                    "global": [],
                    "tenant": self.actions,
                    "scoped": [],
                    "restrictive_flags": ["personal_only"],
                },
            )
        if path == "/v1/check":
            return httpx.Response(200, json={"decision": "allow", "revision": self.revision})
        if path == "/v1/events":
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=self._feed())
        return httpx.Response(404)
