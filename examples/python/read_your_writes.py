"""Read-your-writes across Konklav's two Python packages.

An operator's tool grants a role through the control plane with
`konklav-control-plane`; a relying system deciding with `konklav-relying`
waits for that write's cursor and then allows what the role grants. The
packages don't import each other: the cursor, a plain `int`, is all they
share.

Run it against any Konklav whose control plane you hold a token for:

    uv run read_your_writes.py --control URL --subject URL --relying URL \\
        --issuer ISSUER --audience AUDIENCE --token TOKEN
"""

import argparse
import asyncio
import uuid
from dataclasses import dataclass

import httpx
from konklav_relying import RelyingClient

from konklav_control_plane import BearerToken, ControlPlaneClient

PASSWORD = "correct horse battery"
REQUIREMENTS = {"tenant": ["document:read"]}


@dataclass
class Konklav:
    control: str
    subject: str
    relying: str
    issuer: str
    audience: str
    token: str


def step(text: str) -> None:
    print(f"- {text}")


async def tenant_token(konklav: Konklav, email: str, tenant: str) -> str:
    """Signs in as the person and selects the tenant, as an app would."""
    async with httpx.AsyncClient(base_url=konklav.subject) as http:
        login = await http.post("/v1/login/password", json={"identifier": email, "password": PASSWORD})
        login.raise_for_status()
        identity = login.json()["access_token"]
        selected = await http.post(
            "/v1/login/tenant", json={"tenant": tenant}, headers={"authorization": f"Bearer {identity}"}
        )
        selected.raise_for_status()
        return str(selected.json()["access_token"])


async def run(konklav: Konklav) -> str:
    """Returns the final decision: `allow` when read-your-writes held."""
    async with ControlPlaneClient(konklav.control, auth=BearerToken(konklav.token)) as control:
        await control.catalog.put({"actions": [{"name": "document:read"}]})
        tenant = str(uuid.uuid4())
        await control.tenants.create(tenant, {})
        await control.roles.put(tenant, "reader", {"policies": [{"action": "document:read", "effect": "allow"}]})

        email = f"{uuid.uuid4().hex}@example.com"
        person = str(uuid.uuid4())
        await control.subjects.create(person, {"kind": "human"})
        await control.credentials.create(person, {"kind": "password", "identifier": email, "password": PASSWORD})
        membership = str(uuid.uuid4())
        await control.memberships.create(membership, {"subject": person, "tenant": tenant})
        step(f"created tenant {tenant} with a reader role, and a member without it")

        # The relying system's own service principal, whose key it logs in with.
        service = str(uuid.uuid4())
        await control.subjects.create(service, {"kind": "service"})
        key = await control.credentials.create(service, {"kind": "secret_key"})
        key_id, secret = key["secret_keys"]["a"].split(".", 1)

        relying = RelyingClient(
            relying_url=konklav.relying,
            subject_url=konklav.subject,
            key_id=key_id,
            secret=secret,
            issuer=konklav.issuer,
            audience=konklav.audience,
        )
        await relying.start()
        try:
            token = await tenant_token(konklav, email, tenant)
            before = await relying.decide(token, REQUIREMENTS)
            step(f"before the grant, document:read is {before['decision']}")

            written = await control.assignments.assign_to_membership(membership, {"role": "reader"})
            step(f"assigned the reader role; the write's cursor is {written.cursor}")
            assert written.cursor is not None
            reached = await relying.await_cursor(written.cursor)
            step(f"the relying client {'reached' if reached else 'did not reach'} that cursor")

            after = await relying.decide(token, REQUIREMENTS)
            step(f"after the grant, document:read is {after['decision']}")
            return str(after["decision"])
        finally:
            await relying.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("control", "subject", "relying", "issuer", "audience", "token"):
        parser.add_argument(f"--{name}", required=True)
    decision = asyncio.run(run(Konklav(**vars(parser.parse_args()))))
    raise SystemExit(0 if decision == "allow" else 1)


if __name__ == "__main__":
    main()
