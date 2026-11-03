"""Every client method against a real Konklav, with the async client (the
sync one is generated from it and checked against the same mock tests)."""

import base64
import hashlib
import secrets
import uuid

import httpx
import pytest

from konklav_control_plane import BearerToken, ControlPlaneClient, Forbidden, NotFound, SecretKey

pytestmark = pytest.mark.anyio

PASSWORD = "correct horse battery"

CATALOG = {
    "actions": [{"name": "document:read"}, {"name": "document:write"}, {"name": "project:read"}],
    "groups": [{"name": "document:all", "actions": ["document:read", "document:write"]}],
    "scope_kinds": [{"name": "project"}, {"name": "document", "registered": True}],
    "facts": [
        {"key": "tenant_type", "target": "tenant", "type": "string", "portable": True},
        {"key": "member_number", "target": "membership", "type": "string"},
        {"key": "data_range", "target": "share", "type": "date_range"},
    ],
    "session_flags": [{"name": "personal_only", "kind": "restrictive", "requestable": True}],
}


def new_id() -> str:
    return str(uuid.uuid4())


def operator(konklav):
    return ControlPlaneClient(konklav["control"], auth=BearerToken(konklav["bootstrap_token"]))


async def catalog(client):
    await client.catalog.put(CATALOG)


async def tenant(client, **body):
    id = new_id()
    created = await client.tenants.create(id, body)
    assert created.created is True
    return id


async def human(client, email):
    id = new_id()
    await client.subjects.create(id, {"kind": "human"})
    await client.credentials.create(id, {"kind": "password", "identifier": email, "password": PASSWORD})
    return id


async def login(konklav, email, password=PASSWORD):
    async with httpx.AsyncClient() as http:
        reply = await http.post(
            f"{konklav['subject']}/v1/login/password", json={"identifier": email, "password": password}
        )
    return reply


async def test_tenants_and_memberships(konklav):
    async with operator(konklav) as client:
        await catalog(client)
        assert (await client.catalog.get())["actions"]
        id = await tenant(client, facts={"tenant_type": "client"})
        again = await client.tenants.create(id, {"facts": {"tenant_type": "client"}})
        assert (again.created, again.value["id"]) == (False, id)
        assert (await client.tenants.get(id))["facts"] == {"tenant_type": "client"}
        page = await client.tenants.list(parent="root", limit=1)
        assert len(page["tenants"]) == 1 and page["next"] is not None
        assert id in [t["id"] async for t in client.tenants.iter(parent="root", limit=1)]
        facts = await client.tenants.set_facts(id, {"tenant_type": "personal"})
        assert facts.value["facts"] == {"tenant_type": "personal"}
        suspended = await client.tenants.set_state(id, {"state": "suspended"})
        assert suspended.value["state"] == "suspended"
        await client.tenants.set_state(id, {"state": "active"})

        subject = await human(client, f"{new_id()}@example.com")
        membership = new_id()
        created = await client.memberships.create(membership, {"subject": subject, "tenant": id})
        assert created.created is True and created.cursor is not None
        assert (await client.memberships.get(membership))["subject_id"] == subject
        assert [m["id"] for m in await client.memberships.list(id)] == [membership]
        facts = await client.memberships.set_facts(membership, {"member_number": "m-1"})
        assert facts.value["facts"] == {"member_number": "m-1"}
        ended = await client.memberships.end(membership)
        assert ended.value["state"] == "ended"
        assert await client.memberships.list(id, active=True) == []


async def test_subjects_credentials_and_sessions(konklav):
    async with operator(konklav) as client:
        await catalog(client)
        email = f"{new_id()}@example.com"
        subject = await human(client, email)
        detail = await client.subjects.get(subject)
        (password,) = detail["credentials"]
        assert [s["id"] async for s in client.subjects.iter(identifier=email)] == [subject]
        assert (await client.subjects.list(kind="human", identifier=email))["subjects"][0]["id"] == subject

        session = (await login(konklav, email)).json()
        sessions = await client.sessions.list(subject=subject, active=True)
        (found,) = sessions["sessions"]
        assert [s["id"] async for s in client.sessions.iter(subject=subject)] == [found["id"]]
        assert (await client.sessions.get(found["id"]))["subject_id"] == subject
        assert session["access_token"]

        flags = await client.credentials.set_session_flags(password["id"], {"session_flags": ["personal_only"]})
        assert flags["session_flags"] == ["personal_only"]
        glass = await client.credentials.set_break_glass(password["id"], {"break_glass": True})
        assert glass["break_glass"] is True
        replaced = await client.credentials.replace_password(password["id"], {"password": "a brand new password"})
        assert replaced.value["replaces"] == password["id"]
        assert (await login(konklav, email)).status_code == 401
        revoked = await client.credentials.revoke(replaced.value["id"], {"reason": "lost laptop"})
        assert revoked.value["revoked_reason"] == "lost laptop"

        service = new_id()
        await client.subjects.create(service, {"kind": "service"})
        key = await client.credentials.create(service, {"kind": "secret_key"})
        rotated = await client.credentials.rotate_slot(key.value["credential"]["id"], "b")
        assert (rotated["slot"], rotated["secret_key"].startswith(key.value["credential"]["id"])) == ("b", True)

        email = f"{new_id()}@example.com"
        other = await human(client, email)
        await login(konklav, email)
        ended = await client.sessions.revoke({"subject": other})
        assert len(ended.value["revoked"]) == 1 and ended.cursor is not None
        disabled = await client.subjects.disable(other)
        assert disabled.value["state"] == "disabled"
        enabled = await client.subjects.enable(other)
        assert enabled.value["state"] == "active"


async def test_roles_assignments_and_explanations(konklav):
    async with operator(konklav) as client:
        await catalog(client)
        template = await client.templates.put("reader", {"policies": [{"action": "document:read", "effect": "allow"}]})
        assert template.value["key"] == "reader"
        assert (await client.templates.get("reader"))["policies"][0]["action"] == "document:read"
        assert "reader" in [t["key"] for t in await client.templates.list()]

        id = await tenant(client)
        role = await client.roles.put(id, "writer", {"policies": [{"action": "document:all", "effect": "allow"}]})
        assert role.cursor is not None
        assert (await client.roles.get(id, "writer"))["key"] == "writer"
        assert "writer" in [r["key"] for r in await client.roles.list(id)]

        subject = await human(client, f"{new_id()}@example.com")
        membership = new_id()
        await client.memberships.create(membership, {"subject": subject, "tenant": id})
        assigned = await client.assignments.assign_to_membership(membership, {"role": "writer"})
        entitlements = await client.entitlements.get(subject, tenant=id)
        assert "document:read" in entitlements["tenant"]
        explained = await client.explain.entitlement(subject, action="document:read", tenant=id)
        assert explained["action"] == "document:read"
        decision = await client.explain.decision(subject, {"tenant": id, "requirements": {"tenant": ["document:write"]}})
        assert decision["allowed"] is True
        await client.assignments.unassign(assigned.value["id"])
        assert "document:read" not in (await client.entitlements.get(subject, tenant=id))["tenant"]
        deleted = await client.roles.delete(id, "writer")
        assert deleted.cursor is not None
        with pytest.raises(NotFound):
            await client.roles.get(id, "writer")

        await client.roles.put("root", "auditor", {"policies": [{"action": "project:read", "effect": "allow"}]})
        global_assignment = await client.assignments.assign_global(subject, {"role": "auditor"})
        assert [a["id"] for a in await client.assignments.list_global(subject)] == [global_assignment.value["id"]]


async def test_shares_registered_scopes_and_invites(konklav):
    async with operator(konklav) as client:
        await catalog(client)
        owner, recipient = await tenant(client), await tenant(client)
        await client.roles.put(recipient, "member", {"policies": [{"action": "document:read", "effect": "allow"}]})
        share = new_id()
        terms = {
            "owner": owner,
            "recipient": recipient,
            "scope": {"kind": "project", "id": "p-1"},
            "actions": ["document:read"],
        }
        offered = await client.shares.offer(share, terms)
        assert offered.value["state"] == "offered" and offered.cursor is not None
        assert (await client.shares.get(share))["state"] == "offered"
        accepted = await client.shares.accept(share)
        assert accepted.value["state"] == "accepted"
        assert [s["id"] for s in (await client.shares.list(recipient, side="recipient"))["shares"]] == [share]
        revoked = await client.shares.revoke(share, {"by": "owner"})
        assert revoked.value["state"] == "revoked"

        recorded = await client.registered_scopes.record("document", "d-1", {"tenant": owner})
        assert recorded.value["tenant"] == owner and recorded.cursor is not None
        batch = await client.registered_scopes.change(
            {"changes": [{"op": "record", "kind": "document", "id": "d-2", "tenant": owner}]}
        )
        assert batch.value["scopes"][0]["id"] == "d-2" and batch.cursor is not None
        removed = await client.registered_scopes.remove("document", "d-1")
        assert removed.value["state"] == "removed"

        invite = await client.invites.create({"email": "new@example.com", "tenant": recipient, "roles": ["member"]})
        assert invite.value["invite_id"] and invite.cursor is not None
        assert "token" not in invite.value


async def test_oidc_clients(konklav):
    async with operator(konklav) as client:
        definition = {
            "kind": "confidential",
            "redirect_uris": ["https://app.example/callback"],
            "scopes": ["openid"],
            "audience": "app",
        }
        put = await client.oidc_clients.put("app", definition)
        assert (put["id"], put["has_secret"]) == ("app", False)
        secret = await client.oidc_clients.new_secret("app")
        assert secret["client_secret"]
        assert (await client.oidc_clients.get("app"))["has_secret"] is True
        assert "app" in [c["id"] for c in await client.oidc_clients.list()]
        assert (await client.oidc_clients.disable("app"))["disabled_at"] is not None


async def test_imports(konklav):
    async with operator(konklav) as client:
        subject, credential = new_id(), new_id()
        imported = await client.imports.subjects({"subjects": [{"id": subject, "kind": "human"}]})
        assert imported["imported"] == 1
        email = f"{new_id()}@example.com"
        credentials = {"credentials": [{"id": credential, "subject": subject, "identifier": email, "kind": "email_link"}]}
        assert (await client.imports.credentials(credentials))["imported"] == 1
        seed = base64.b32encode(secrets.token_bytes(20)).decode()
        factors = {"factors": [{"id": new_id(), "subject": subject, "kind": "totp", "seed_base32": seed}]}
        assert (await client.imports.mfa_factors(factors))["imported"] == 1
        session = new_id()
        refresh = f"{session}.{secrets.token_hex(16)}"
        sessions = {
            "sessions": [
                {
                    "id": session,
                    "subject": subject,
                    "credential": credential,
                    "stage": "identity",
                    "amr": ["email"],
                    "auth_time": "2026-10-01T00:00:00Z",
                    "version": 1,
                    "refresh_hash": hashlib.sha256(refresh.encode()).hexdigest(),
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ]
        }
        assert (await client.imports.sessions(sessions))["imported"] == 1
        assert (await client.sessions.get(session))["subject_id"] == subject


async def test_signing_keys(fresh_konklav):
    async with operator(fresh_konklav) as client:
        (key,) = await client.signing_keys.list()
        revoked = await client.signing_keys.revoke(key["kid"])
        assert revoked["kid"] == key["kid"]


async def test_a_narrow_operator_is_refused_other_areas(konklav):
    async with operator(konklav) as client:
        await client.roles.put(
            "root", "tenant-admin", {"policies": [{"action": "konklav:tenants:manage", "effect": "allow"}]}
        )
        service = new_id()
        await client.subjects.create(service, {"kind": "service"})
        key = await client.credentials.create(service, {"kind": "secret_key"})
        await client.assignments.assign_global(service, {"role": "tenant-admin"})
    key_id, secret = key.value["secret_keys"]["a"].split(".", 1)
    auth = SecretKey(subject_url=konklav["subject"], key_id=key_id, secret=secret)
    async with ControlPlaneClient(konklav["control"], auth=auth) as narrow:
        assert (await narrow.tenants.create(new_id(), {})).created is True
        with pytest.raises(Forbidden):
            await narrow.subjects.list()


async def test_creates_report_repeats(konklav):
    async with operator(konklav) as client:
        await catalog(client)
        id = await tenant(client)
        await client.roles.put(id, "reader", {"policies": [{"action": "document:read", "effect": "allow"}]})
        subject = await human(client, f"{new_id()}@example.com")
        membership = new_id()
        await client.memberships.create(membership, {"subject": subject, "tenant": id})
        assignment = {"id": new_id(), "role": "reader"}
        first = await client.assignments.assign_to_membership(membership, assignment)
        again = await client.assignments.assign_to_membership(membership, assignment)
        assert (first.created, again.created, again.value["id"]) == (True, False, assignment["id"])

        service = new_id()
        await client.subjects.create(service, {"kind": "service"})
        key = {"id": new_id(), "kind": "secret_key"}
        created = await client.credentials.create(service, key)
        repeated = await client.credentials.create(service, key)
        assert (created.created, repeated.created) == (True, False)
        assert repeated.value["secret_keys"]["a"] != created.value["secret_keys"]["a"]

        invite = {"id": new_id(), "email": "again@example.com"}
        assert (await client.invites.create(invite)).created is True
        assert (await client.invites.create(invite)).created is False
