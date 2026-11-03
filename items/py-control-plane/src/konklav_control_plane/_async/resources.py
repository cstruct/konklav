"""The control plane's operations, grouped as the API document tags them.

Path arguments come first, then the request body as `body`, then query
parameters by keyword. Writes that answer with a change-feed cursor return
a `Written`, as do idempotent creates, which also say whether they created.
"""

from __future__ import annotations

import builtins
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, cast

from .. import types
from .._common import Written, operation, path

if TYPE_CHECKING:
    from .client import ControlPlaneClient


class _Resource:
    def __init__(self, client: ControlPlaneClient) -> None:
        self._client = client


class Tenants(_Resource):
    """Tenants. Where a tenant is named, `"root"` names the root tenant."""

    @operation("list_tenants")
    async def list(
        self, *, parent: str | None = None, before: str | None = None, limit: int | None = None
    ) -> types.TenantPage:
        params = {"parent": parent, "before": before, "limit": limit}
        return cast(types.TenantPage, await self._client._get(path("tenants"), params))

    async def iter(self, *, parent: str | None = None, limit: int | None = None) -> AsyncIterator[types.Tenant]:
        """Every tenant, page after page."""
        async for tenant in self._client._pages(path("tenants"), "tenants", {"parent": parent, "limit": limit}):
            yield cast(types.Tenant, tenant)

    @operation("get_tenant")
    async def get(self, id: str) -> types.Tenant:
        return cast(types.Tenant, await self._client._get(path("tenants", id)))

    @operation("create_tenant")
    async def create(self, id: str, body: types.CreateTenant) -> Written[types.Tenant]:
        return await self._client._write("PUT", path("tenants", id), json=body, create=True)

    @operation("set_tenant_facts")
    async def set_facts(self, id: str, body: dict[str, Any]) -> Written[types.Tenant]:
        return await self._client._write("PUT", path("tenants", id, "facts"), json=body)

    @operation("set_tenant_state")
    async def set_state(self, id: str, body: types.SetTenantState) -> Written[types.Tenant]:
        return await self._client._write("PUT", path("tenants", id, "state"), json=body)


class Memberships(_Resource):
    @operation("list_memberships")
    async def list(self, tenant: str, *, active: bool | None = None) -> builtins.list[types.Membership]:
        response = await self._client._get(path("tenants", tenant, "memberships"), {"active": active})
        return cast(builtins.list[types.Membership], response)

    @operation("get_membership")
    async def get(self, id: str) -> types.MembershipDetail:
        return cast(types.MembershipDetail, await self._client._get(path("memberships", id)))

    @operation("create_membership")
    async def create(self, id: str, body: types.CreateMembership) -> Written[types.Membership]:
        return await self._client._write("PUT", path("memberships", id), json=body, create=True)

    @operation("end_membership")
    async def end(self, id: str) -> Written[types.Membership]:
        return await self._client._write("POST", path("memberships", id, "end"))

    @operation("set_membership_facts")
    async def set_facts(self, id: str, body: dict[str, Any]) -> Written[types.Membership]:
        return await self._client._write("PUT", path("memberships", id, "facts"), json=body)


class Subjects(_Resource):
    @operation("list_subjects")
    async def list(
        self,
        *,
        kind: types.SubjectKind | None = None,
        identifier: str | None = None,
        before: str | None = None,
        limit: int | None = None,
    ) -> types.SubjectPage:
        params = {"kind": kind, "identifier": identifier, "before": before, "limit": limit}
        return cast(types.SubjectPage, await self._client._get(path("subjects"), params))

    async def iter(
        self,
        *,
        kind: types.SubjectKind | None = None,
        identifier: str | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[types.Subject]:
        """Every matching subject, page after page."""
        params = {"kind": kind, "identifier": identifier, "limit": limit}
        async for subject in self._client._pages(path("subjects"), "subjects", params):
            yield cast(types.Subject, subject)

    @operation("get_subject")
    async def get(self, id: str) -> types.SubjectDetail:
        return cast(types.SubjectDetail, await self._client._get(path("subjects", id)))

    @operation("create_subject")
    async def create(self, id: str, body: types.CreateSubject) -> Written[types.Subject]:
        return await self._client._write("PUT", path("subjects", id), json=body, create=True)

    @operation("disable_subject")
    async def disable(self, id: str) -> Written[types.Subject]:
        return await self._client._write("POST", path("subjects", id, "disable"))

    @operation("enable_subject")
    async def enable(self, id: str) -> Written[types.Subject]:
        return await self._client._write("POST", path("subjects", id, "enable"))


class Credentials(_Resource):
    @operation("create_credential")
    async def create(self, subject: str, body: types.CreateCredential) -> Written[types.CreatedCredential]:
        """Generated secrets in the result are shown only this once. Repeating
        a secret key's create with its `id` shows new secrets, and the first
        ones stop working."""
        return await self._client._write("POST", path("subjects", subject, "credentials"), json=body, create=True)

    @operation("revoke_credential")
    async def revoke(self, id: str, body: types.RevokeCredential | None = None) -> Written[types.Credential]:
        return await self._client._write("POST", path("credentials", id, "revoke"), json=body)

    @operation("replace_password")
    async def replace_password(self, id: str, body: types.ReplacePassword) -> Written[types.Credential]:
        return await self._client._write("POST", path("credentials", id, "replace"), json=body, create=True)

    @operation("rotate_secret_slot")
    async def rotate_slot(
        self, id: str, slot: types.SecretSlot, body: types.RotateSlot | None = None
    ) -> types.RotatedSlot:
        """The new secret in the result is shown only this once."""
        response = await self._client._post(path("credentials", id, "slots", slot, "rotate"), body)
        return cast(types.RotatedSlot, response)

    @operation("set_break_glass")
    async def set_break_glass(self, id: str, body: types.BreakGlass) -> types.Credential:
        response = await self._client.request("PUT", path("credentials", id, "break-glass"), json=body)
        return cast(types.Credential, response)

    @operation("set_session_flags")
    async def set_session_flags(self, id: str, body: types.SessionFlags) -> types.Credential:
        response = await self._client.request("PUT", path("credentials", id, "session-flags"), json=body)
        return cast(types.Credential, response)


class Sessions(_Resource):
    @operation("list_sessions")
    async def list(
        self,
        *,
        subject: str | None = None,
        credential: str | None = None,
        active: bool | None = None,
        before: str | None = None,
        limit: int | None = None,
    ) -> types.SessionPage:
        params = {"subject": subject, "credential": credential, "active": active, "before": before, "limit": limit}
        return cast(types.SessionPage, await self._client._get(path("sessions"), params))

    async def iter(
        self,
        *,
        subject: str | None = None,
        credential: str | None = None,
        active: bool | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[types.Session]:
        """Every matching session, page after page."""
        params = {"subject": subject, "credential": credential, "active": active, "limit": limit}
        async for session in self._client._pages(path("sessions"), "sessions", params):
            yield cast(types.Session, session)

    @operation("get_session")
    async def get(self, id: str) -> types.Session:
        return cast(types.Session, await self._client._get(path("sessions", id)))

    @operation("revoke_sessions")
    async def revoke(self, body: types.RevokeSessions) -> Written[types.RevokedSessions]:
        return await self._client._write("POST", path("sessions", "revoke"), json=body)


class SigningKeys(_Resource):
    @operation("list_signing_keys")
    async def list(self) -> builtins.list[types.SigningKey]:
        return cast(builtins.list[types.SigningKey], await self._client._get(path("signing-keys")))

    @operation("revoke_signing_key")
    async def revoke(self, kid: str) -> types.RevokedKey:
        return cast(types.RevokedKey, await self._client._post(path("signing-keys", kid, "revoke")))


class Catalog(_Resource):
    @operation("get_catalog")
    async def get(self) -> types.CatalogDocument:
        return cast(types.CatalogDocument, await self._client._get(path("catalog")))

    @operation("put_catalog")
    async def put(self, body: types.CatalogDocument) -> Written[types.CatalogDocument]:
        """Replaces the whole catalog."""
        return await self._client._write("PUT", path("catalog"), json=body)


class Templates(_Resource):
    @operation("list_templates")
    async def list(self) -> builtins.list[types.Template]:
        return cast(builtins.list[types.Template], await self._client._get(path("templates")))

    @operation("get_template")
    async def get(self, key: str) -> types.Template:
        return cast(types.Template, await self._client._get(path("templates", key)))

    @operation("put_template")
    async def put(self, key: str, body: types.PutTemplate) -> Written[types.Template]:
        return await self._client._write("PUT", path("templates", key), json=body)


class Roles(_Resource):
    """A tenant's roles; the root tenant's are global roles."""

    @operation("list_roles")
    async def list(self, tenant: str) -> builtins.list[types.Role]:
        return cast(builtins.list[types.Role], await self._client._get(path("tenants", tenant, "roles")))

    @operation("get_role")
    async def get(self, tenant: str, key: str) -> types.Role:
        return cast(types.Role, await self._client._get(path("tenants", tenant, "roles", key)))

    @operation("put_role")
    async def put(self, tenant: str, key: str, body: types.PutRole) -> Written[types.Role]:
        return await self._client._write("PUT", path("tenants", tenant, "roles", key), json=body)

    @operation("delete_role")
    async def delete(self, tenant: str, key: str) -> Written[types.Deleted]:
        return await self._client._write("DELETE", path("tenants", tenant, "roles", key))


class Assignments(_Resource):
    @operation("assign_membership_role")
    async def assign_to_membership(self, membership: str, body: types.AssignRole) -> Written[types.RoleAssignment]:
        """Assigns one of the membership's tenant's roles."""
        return await self._client._write("POST", path("memberships", membership, "assignments"), json=body, create=True)

    @operation("assign_global_role")
    async def assign_global(self, subject: str, body: types.AssignRole) -> Written[types.RoleAssignment]:
        """Assigns a global role to a subject directly."""
        return await self._client._write("POST", path("subjects", subject, "global-assignments"), json=body, create=True)

    @operation("list_global_assignments")
    async def list_global(self, subject: str) -> builtins.list[types.RoleAssignment]:
        response = await self._client._get(path("subjects", subject, "global-assignments"))
        return cast(builtins.list[types.RoleAssignment], response)

    @operation("unassign")
    async def unassign(self, id: str) -> Written[types.Deleted]:
        return await self._client._write("DELETE", path("assignments", id))


class Entitlements(_Resource):
    @operation("subject_entitlements")
    async def get(self, subject: str, *, tenant: str | None = None) -> types.Entitlements:
        """What a subject is entitled to: global only, or in `tenant`."""
        response = await self._client._get(path("subjects", subject, "entitlements"), {"tenant": tenant})
        return cast(types.Entitlements, response)


class Explain(_Resource):
    @operation("explain_entitlement")
    async def entitlement(self, subject: str, *, action: str, tenant: str | None = None) -> types.Explanation:
        """Which assignments and policies bear on `action`, and where it ends
        up granted."""
        params = {"action": action, "tenant": tenant}
        return cast(types.Explanation, await self._client._get(path("subjects", subject, "explain"), params))

    @operation("explain_decision")
    async def decision(self, subject: str, body: types.ExplainDecision) -> types.DecisionExplanation:
        response = await self._client._post(path("subjects", subject, "explain-decision"), body)
        return cast(types.DecisionExplanation, response)


class Shares(_Resource):
    @operation("list_shares")
    async def list(self, tenant: str, *, side: types.ShareSide | None = None) -> types.ShareList:
        response = await self._client._get(path("tenants", tenant, "shares"), {"side": side})
        return cast(types.ShareList, response)

    @operation("get_share")
    async def get(self, id: str) -> types.Share:
        return cast(types.Share, await self._client._get(path("shares", id)))

    @operation("offer_share")
    async def offer(self, id: str, body: types.ShareTerms) -> Written[types.Share]:
        """Offers a share, or changes its terms, which offers it again."""
        return await self._client._write("PUT", path("shares", id), json=body)

    @operation("accept_share")
    async def accept(self, id: str) -> Written[types.Share]:
        return await self._client._write("POST", path("shares", id, "accept"))

    @operation("revoke_share")
    async def revoke(self, id: str, body: types.RevokeShare) -> Written[types.Share]:
        return await self._client._write("POST", path("shares", id, "revoke"), json=body)


class RegisteredScopes(_Resource):
    @operation("change_registered_scopes")
    async def change(self, body: types.RegisteredScopeChanges) -> Written[types.RegisteredScopeBatch]:
        """Records and removes up to 1000 scopes, all or nothing."""
        return await self._client._write("POST", path("registered-scopes"), json=body)

    @operation("record_registered_scope")
    async def record(self, kind: str, id: str, body: types.RecordRegisteredScope) -> Written[types.RegisteredScope]:
        return await self._client._write("PUT", path("registered-scopes", kind, id), json=body)

    @operation("remove_registered_scope")
    async def remove(self, kind: str, id: str) -> Written[types.RegisteredScope]:
        return await self._client._write("DELETE", path("registered-scopes", kind, id))


class Invites(_Resource):
    @operation("create_invite")
    async def create(self, body: types.CreateInvite) -> Written[types.CreatedInvite]:
        """The invite's token is delivered to the address, never returned."""
        return await self._client._write("POST", path("invites"), json=body, create=True)


class OidcClients(_Resource):
    @operation("list_oidc_clients")
    async def list(self) -> builtins.list[types.OidcClient]:
        return cast(builtins.list[types.OidcClient], await self._client._get(path("oidc", "clients")))

    @operation("get_oidc_client")
    async def get(self, id: str) -> types.OidcClient:
        return cast(types.OidcClient, await self._client._get(path("oidc", "clients", id)))

    @operation("put_oidc_client")
    async def put(self, id: str, body: types.OidcClientDefinition) -> types.OidcClient:
        """Registers or replaces a client, enabling it if it was disabled."""
        response = await self._client.request("PUT", path("oidc", "clients", id), json=body)
        return cast(types.OidcClient, response)

    @operation("disable_oidc_client")
    async def disable(self, id: str) -> types.OidcClient:
        response = await self._client.request("DELETE", path("oidc", "clients", id))
        return cast(types.OidcClient, response)

    @operation("new_oidc_client_secret")
    async def new_secret(self, id: str) -> types.OidcClientSecret:
        """The secret is shown only this once; the previous one stops working."""
        response = await self._client._post(path("oidc", "clients", id, "secret"))
        return cast(types.OidcClientSecret, response)


class Imports(_Resource):
    """Imports from another system, each all or nothing."""

    @operation("import_subjects")
    async def subjects(self, body: types.ImportSubjects) -> types.Imported:
        return cast(types.Imported, await self._client._post(path("import", "subjects"), body))

    @operation("import_credentials")
    async def credentials(self, body: types.ImportCredentials) -> types.Imported:
        return cast(types.Imported, await self._client._post(path("import", "credentials"), body))

    @operation("import_factors")
    async def mfa_factors(self, body: types.ImportFactors) -> types.Imported:
        """TOTP seeds are sent in plaintext and encrypted by Konklav."""
        return cast(types.Imported, await self._client._post(path("import", "mfa-factors"), body))

    @operation("import_sessions")
    async def sessions(self, body: types.ImportSessions) -> types.Imported:
        return cast(types.Imported, await self._client._post(path("import", "sessions"), body))
