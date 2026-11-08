"""The control plane's operations, grouped as the API document tags them.

Path arguments come first, then the request body as `body`, then query
parameters by keyword. Writes that answer with a change-feed cursor return
a `Written`, as do idempotent creates, which also say whether they created.

Each namespace is generic over its mode: the client's (`Direct`) send each
call, a batch's (`Batched`) only record writes, returning a `Pending` for
what the call will have returned once the batch is sent. Reads exist only
on the client's.
"""

from __future__ import annotations

import builtins
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, cast, overload

from .. import types
from .._common import Call, MetadataFilter, Mode, Pending, Written, metadata_filter, operation, path

if TYPE_CHECKING:
    from .batch import Batch
    from .client import ControlPlaneClient

Direct = Literal[Mode.DIRECT]
Batched = Literal[Mode.BATCH]
M = TypeVar("M", bound=Mode)


# r[impl item.py-control-plane.batch]
class _Resource(Generic[M]):
    def __init__(self, client: ControlPlaneClient, batch: Batch | None = None) -> None:
        self._client = client
        self._batch = batch

    def _do(self, call: Call) -> Any:
        """A write: sent now, or recorded in the batch."""
        if self._batch is not None:
            return self._batch._add(call)
        return self._client._call(call)

    @property
    def _direct(self) -> ControlPlaneClient:
        """The client, for what a batch can't hold."""
        if self._batch is not None:
            raise TypeError("a batch holds only writes; read through the client")
        return self._client


class Tenants(_Resource[M]):
    """Tenants. Where a tenant is named, `"root"` names the root tenant."""

    @operation("list_tenants")
    async def list(
        self: Tenants[Direct],
        *,
        parent: str | None = None,
        metadata: MetadataFilter | None = None,
        before: str | None = None,
        limit: int | None = None,
    ) -> types.TenantPage:
        params = {"parent": parent, "metadata": metadata_filter(metadata), "before": before, "limit": limit}
        return cast(types.TenantPage, await self._direct._get(path("tenants"), params))

    async def iter(
        self: Tenants[Direct],
        *,
        parent: str | None = None,
        metadata: MetadataFilter | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[types.Tenant]:
        """Every matching tenant, page after page."""
        params = {"parent": parent, "metadata": metadata_filter(metadata), "limit": limit}
        async for tenant in self._direct._pages(path("tenants"), "tenants", params):
            yield cast(types.Tenant, tenant)

    @operation("get_tenant")
    async def get(self: Tenants[Direct], id: str) -> types.Tenant:
        return cast(types.Tenant, await self._direct._get(path("tenants", id)))

    @overload
    async def create(self: Tenants[Direct], id: str, body: types.CreateTenant) -> Written[types.Tenant]: ...

    @overload
    def create(self: Tenants[Batched], id: str, body: types.CreateTenant) -> Pending[Written[types.Tenant]]: ...

    @operation("create_tenant")
    def create(self, id: str, body: types.CreateTenant) -> Any:
        return self._do(Call("PUT", path("tenants", id), json=body, create=True, written=True))

    @overload
    async def set_facts(self: Tenants[Direct], id: str, body: dict[str, Any]) -> Written[types.Tenant]: ...

    @overload
    def set_facts(self: Tenants[Batched], id: str, body: dict[str, Any]) -> Pending[Written[types.Tenant]]: ...

    @operation("set_tenant_facts")
    def set_facts(self, id: str, body: dict[str, Any]) -> Any:
        return self._do(Call("PUT", path("tenants", id, "facts"), json=body, written=True))

    @overload
    async def set_state(self: Tenants[Direct], id: str, body: types.SetTenantState) -> Written[types.Tenant]: ...

    @overload
    def set_state(self: Tenants[Batched], id: str, body: types.SetTenantState) -> Pending[Written[types.Tenant]]: ...

    @operation("set_tenant_state")
    def set_state(self, id: str, body: types.SetTenantState) -> Any:
        return self._do(Call("PUT", path("tenants", id, "state"), json=body, written=True))

    @overload
    async def patch_metadata(
        self: Tenants[Direct], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.Tenant]: ...

    @overload
    def patch_metadata(
        self: Tenants[Batched], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.Tenant]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_tenant_metadata")
    def patch_metadata(self, id: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("tenants", id, "metadata"), json=body, written=True, if_match=if_match))


class Memberships(_Resource[M]):
    @operation("list_memberships")
    async def list(
        self: Memberships[Direct],
        tenant: str,
        *,
        active: bool | None = None,
        metadata: MetadataFilter | None = None,
    ) -> builtins.list[types.Membership]:
        params = {"active": active, "metadata": metadata_filter(metadata)}
        response = await self._direct._get(path("tenants", tenant, "memberships"), params)
        return cast(builtins.list[types.Membership], response)

    @operation("get_membership")
    async def get(self: Memberships[Direct], id: str) -> types.MembershipDetail:
        return cast(types.MembershipDetail, await self._direct._get(path("memberships", id)))

    @overload
    async def create(self: Memberships[Direct], id: str, body: types.CreateMembership) -> Written[types.Membership]: ...

    @overload
    def create(self: Memberships[Batched], id: str, body: types.CreateMembership) -> Pending[Written[types.Membership]]: ...

    @operation("create_membership")
    def create(self, id: str, body: types.CreateMembership) -> Any:
        return self._do(Call("PUT", path("memberships", id), json=body, create=True, written=True))

    @overload
    async def end(self: Memberships[Direct], id: str) -> Written[types.Membership]: ...

    @overload
    def end(self: Memberships[Batched], id: str) -> Pending[Written[types.Membership]]: ...

    @operation("end_membership")
    def end(self, id: str) -> Any:
        return self._do(Call("POST", path("memberships", id, "end"), written=True))

    @overload
    async def set_facts(self: Memberships[Direct], id: str, body: dict[str, Any]) -> Written[types.Membership]: ...

    @overload
    def set_facts(self: Memberships[Batched], id: str, body: dict[str, Any]) -> Pending[Written[types.Membership]]: ...

    @operation("set_membership_facts")
    def set_facts(self, id: str, body: dict[str, Any]) -> Any:
        return self._do(Call("PUT", path("memberships", id, "facts"), json=body, written=True))

    @overload
    async def patch_metadata(
        self: Memberships[Direct], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.Membership]: ...

    @overload
    def patch_metadata(
        self: Memberships[Batched], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.Membership]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_membership_metadata")
    def patch_metadata(self, id: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("memberships", id, "metadata"), json=body, written=True, if_match=if_match))


class Subjects(_Resource[M]):
    @operation("list_subjects")
    async def list(
        self: Subjects[Direct],
        *,
        kind: types.SubjectKind | None = None,
        identifier: str | None = None,
        metadata: MetadataFilter | None = None,
        before: str | None = None,
        limit: int | None = None,
    ) -> types.SubjectPage:
        params = {
            "kind": kind,
            "identifier": identifier,
            "metadata": metadata_filter(metadata),
            "before": before,
            "limit": limit,
        }
        return cast(types.SubjectPage, await self._direct._get(path("subjects"), params))

    async def iter(
        self: Subjects[Direct],
        *,
        kind: types.SubjectKind | None = None,
        identifier: str | None = None,
        metadata: MetadataFilter | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[types.Subject]:
        """Every matching subject, page after page."""
        params = {"kind": kind, "identifier": identifier, "metadata": metadata_filter(metadata), "limit": limit}
        async for subject in self._direct._pages(path("subjects"), "subjects", params):
            yield cast(types.Subject, subject)

    @operation("get_subject")
    async def get(self: Subjects[Direct], id: str) -> types.SubjectDetail:
        return cast(types.SubjectDetail, await self._direct._get(path("subjects", id)))

    @overload
    async def create(self: Subjects[Direct], id: str, body: types.CreateSubject) -> Written[types.Subject]: ...

    @overload
    def create(self: Subjects[Batched], id: str, body: types.CreateSubject) -> Pending[Written[types.Subject]]: ...

    @operation("create_subject")
    def create(self, id: str, body: types.CreateSubject) -> Any:
        return self._do(Call("PUT", path("subjects", id), json=body, create=True, written=True))

    @overload
    async def disable(self: Subjects[Direct], id: str) -> Written[types.Subject]: ...

    @overload
    def disable(self: Subjects[Batched], id: str) -> Pending[Written[types.Subject]]: ...

    @operation("disable_subject")
    def disable(self, id: str) -> Any:
        return self._do(Call("POST", path("subjects", id, "disable"), written=True))

    @overload
    async def enable(self: Subjects[Direct], id: str) -> Written[types.Subject]: ...

    @overload
    def enable(self: Subjects[Batched], id: str) -> Pending[Written[types.Subject]]: ...

    @operation("enable_subject")
    def enable(self, id: str) -> Any:
        return self._do(Call("POST", path("subjects", id, "enable"), written=True))

    @overload
    async def patch_metadata(
        self: Subjects[Direct], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.Subject]: ...

    @overload
    def patch_metadata(
        self: Subjects[Batched], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.Subject]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_subject_metadata")
    def patch_metadata(self, id: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("subjects", id, "metadata"), json=body, written=True, if_match=if_match))


class Credentials(_Resource[M]):
    @overload
    async def create(self: Credentials[Direct], subject: str, body: types.CreateCredential) -> Written[types.CreatedCredential]: ...

    @overload
    def create(self: Credentials[Batched], subject: str, body: types.CreateCredential) -> Pending[Written[types.CreatedCredential]]: ...

    @operation("create_credential")
    def create(self, subject: str, body: types.CreateCredential) -> Any:
        """Generated secrets in the result are shown only this once. Repeating
        a secret key's create with its `id` shows new secrets, and the first
        ones stop working."""
        return self._do(Call("POST", path("subjects", subject, "credentials"), json=body, create=True, written=True))

    @overload
    async def revoke(self: Credentials[Direct], id: str, body: types.RevokeCredential | None = None) -> Written[types.Credential]: ...

    @overload
    def revoke(self: Credentials[Batched], id: str, body: types.RevokeCredential | None = None) -> Pending[Written[types.Credential]]: ...

    @operation("revoke_credential")
    def revoke(self, id: str, body: types.RevokeCredential | None = None) -> Any:
        return self._do(Call("POST", path("credentials", id, "revoke"), json=body, written=True))

    @overload
    async def replace_password(self: Credentials[Direct], id: str, body: types.ReplacePassword) -> Written[types.Credential]: ...

    @overload
    def replace_password(self: Credentials[Batched], id: str, body: types.ReplacePassword) -> Pending[Written[types.Credential]]: ...

    @operation("replace_password")
    def replace_password(self, id: str, body: types.ReplacePassword) -> Any:
        return self._do(Call("POST", path("credentials", id, "replace"), json=body, create=True, written=True))

    @overload
    async def rotate_slot(
        self: Credentials[Direct], id: str, slot: types.SecretSlot, body: types.RotateSlot | None = None
    ) -> types.RotatedSlot: ...

    @overload
    def rotate_slot(
        self: Credentials[Batched], id: str, slot: types.SecretSlot, body: types.RotateSlot | None = None
    ) -> Pending[types.RotatedSlot]: ...

    @operation("rotate_secret_slot")
    def rotate_slot(
        self, id: str, slot: types.SecretSlot, body: types.RotateSlot | None = None
    ) -> Any:
        """The new secret in the result is shown only this once."""
        return self._do(Call("POST", path("credentials", id, "slots", slot, "rotate"), json=body))

    @overload
    async def set_slot_expiry(
        self: Credentials[Direct], id: str, slot: types.SecretSlot, body: types.SlotExpiry
    ) -> types.Credential: ...

    @overload
    def set_slot_expiry(
        self: Credentials[Batched], id: str, slot: types.SecretSlot, body: types.SlotExpiry
    ) -> Pending[types.Credential]: ...

    @operation("set_slot_expiry")
    def set_slot_expiry(self, id: str, slot: types.SecretSlot, body: types.SlotExpiry) -> Any:
        """The slot keeps its secret; `expires_at` `None` makes it never expire."""
        return self._do(Call("PUT", path("credentials", id, "slots", slot, "expiry"), json=body))

    @overload
    async def set_break_glass(self: Credentials[Direct], id: str, body: types.BreakGlass) -> types.Credential: ...

    @overload
    def set_break_glass(self: Credentials[Batched], id: str, body: types.BreakGlass) -> Pending[types.Credential]: ...

    @operation("set_break_glass")
    def set_break_glass(self, id: str, body: types.BreakGlass) -> Any:
        return self._do(Call("PUT", path("credentials", id, "break-glass"), json=body))

    @overload
    async def set_session_flags(self: Credentials[Direct], id: str, body: types.SessionFlags) -> types.Credential: ...

    @overload
    def set_session_flags(self: Credentials[Batched], id: str, body: types.SessionFlags) -> Pending[types.Credential]: ...

    @operation("set_session_flags")
    def set_session_flags(self, id: str, body: types.SessionFlags) -> Any:
        return self._do(Call("PUT", path("credentials", id, "session-flags"), json=body))

    @overload
    async def patch_metadata(
        self: Credentials[Direct], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.Credential]: ...

    @overload
    def patch_metadata(
        self: Credentials[Batched], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.Credential]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_credential_metadata")
    def patch_metadata(self, id: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("credentials", id, "metadata"), json=body, written=True, if_match=if_match))


class Sessions(_Resource[M]):
    @operation("list_sessions")
    async def list(
        self: Sessions[Direct],
        *,
        subject: str | None = None,
        credential: str | None = None,
        active: bool | None = None,
        before: str | None = None,
        limit: int | None = None,
    ) -> types.SessionPage:
        params = {"subject": subject, "credential": credential, "active": active, "before": before, "limit": limit}
        return cast(types.SessionPage, await self._direct._get(path("sessions"), params))

    async def iter(
        self: Sessions[Direct],
        *,
        subject: str | None = None,
        credential: str | None = None,
        active: bool | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[types.Session]:
        """Every matching session, page after page."""
        params = {"subject": subject, "credential": credential, "active": active, "limit": limit}
        async for session in self._direct._pages(path("sessions"), "sessions", params):
            yield cast(types.Session, session)

    @operation("get_session")
    async def get(self: Sessions[Direct], id: str) -> types.Session:
        return cast(types.Session, await self._direct._get(path("sessions", id)))

    @overload
    async def revoke(self: Sessions[Direct], body: types.RevokeSessions) -> Written[types.RevokedSessions]: ...

    @overload
    def revoke(self: Sessions[Batched], body: types.RevokeSessions) -> Pending[Written[types.RevokedSessions]]: ...

    @operation("revoke_sessions")
    def revoke(self, body: types.RevokeSessions) -> Any:
        return self._do(Call("POST", path("sessions", "revoke"), json=body, written=True))


class SigningKeys(_Resource[M]):
    @operation("list_signing_keys")
    async def list(self: SigningKeys[Direct]) -> builtins.list[types.SigningKey]:
        return cast(builtins.list[types.SigningKey], await self._direct._get(path("signing-keys")))

    @overload
    async def revoke(self: SigningKeys[Direct], kid: str) -> types.RevokedKey: ...

    @overload
    def revoke(self: SigningKeys[Batched], kid: str) -> Pending[types.RevokedKey]: ...

    @operation("revoke_signing_key")
    def revoke(self, kid: str) -> Any:
        return self._do(Call("POST", path("signing-keys", kid, "revoke")))


class Catalog(_Resource[M]):
    @operation("get_catalog")
    async def get(self: Catalog[Direct]) -> types.CatalogDocument:
        return cast(types.CatalogDocument, await self._direct._get(path("catalog")))

    @overload
    async def put(self: Catalog[Direct], body: types.CatalogDocument) -> Written[types.CatalogDocument]: ...

    @overload
    def put(self: Catalog[Batched], body: types.CatalogDocument) -> Pending[Written[types.CatalogDocument]]: ...

    @operation("put_catalog")
    def put(self, body: types.CatalogDocument) -> Any:
        """Replaces the whole catalog."""
        return self._do(Call("PUT", path("catalog"), json=body, written=True))


class Templates(_Resource[M]):
    @operation("list_templates")
    async def list(self: Templates[Direct], *, metadata: MetadataFilter | None = None) -> builtins.list[types.Template]:
        response = await self._direct._get(path("templates"), {"metadata": metadata_filter(metadata)})
        return cast(builtins.list[types.Template], response)

    @operation("get_template")
    async def get(self: Templates[Direct], key: str) -> types.Template:
        return cast(types.Template, await self._direct._get(path("templates", key)))

    @overload
    async def put(self: Templates[Direct], key: str, body: types.PutTemplate) -> Written[types.Template]: ...

    @overload
    def put(self: Templates[Batched], key: str, body: types.PutTemplate) -> Pending[Written[types.Template]]: ...

    @operation("put_template")
    def put(self, key: str, body: types.PutTemplate) -> Any:
        return self._do(Call("PUT", path("templates", key), json=body, written=True))

    @overload
    async def patch_metadata(
        self: Templates[Direct], key: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.Template]: ...

    @overload
    def patch_metadata(
        self: Templates[Batched], key: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.Template]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_template_metadata")
    def patch_metadata(self, key: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("templates", key, "metadata"), json=body, written=True, if_match=if_match))


class Roles(_Resource[M]):
    """A tenant's roles; the root tenant's are global roles."""

    @operation("list_roles")
    async def list(
        self: Roles[Direct], tenant: str, *, metadata: MetadataFilter | None = None
    ) -> builtins.list[types.Role]:
        response = await self._direct._get(path("tenants", tenant, "roles"), {"metadata": metadata_filter(metadata)})
        return cast(builtins.list[types.Role], response)

    @operation("get_role")
    async def get(self: Roles[Direct], tenant: str, key: str) -> types.Role:
        return cast(types.Role, await self._direct._get(path("tenants", tenant, "roles", key)))

    @overload
    async def put(self: Roles[Direct], tenant: str, key: str, body: types.PutRole) -> Written[types.Role]: ...

    @overload
    def put(self: Roles[Batched], tenant: str, key: str, body: types.PutRole) -> Pending[Written[types.Role]]: ...

    @operation("put_role")
    def put(self, tenant: str, key: str, body: types.PutRole) -> Any:
        return self._do(Call("PUT", path("tenants", tenant, "roles", key), json=body, written=True))

    @overload
    async def delete(self: Roles[Direct], tenant: str, key: str) -> Written[types.Deleted]: ...

    @overload
    def delete(self: Roles[Batched], tenant: str, key: str) -> Pending[Written[types.Deleted]]: ...

    @operation("delete_role")
    def delete(self, tenant: str, key: str) -> Any:
        return self._do(Call("DELETE", path("tenants", tenant, "roles", key), written=True))

    @overload
    async def patch_metadata(
        self: Roles[Direct], tenant: str, key: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.Role]: ...

    @overload
    def patch_metadata(
        self: Roles[Batched], tenant: str, key: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.Role]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_role_metadata")
    def patch_metadata(self, tenant: str, key: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("tenants", tenant, "roles", key, "metadata"), json=body, written=True, if_match=if_match))


class Assignments(_Resource[M]):
    @overload
    async def assign_to_membership(self: Assignments[Direct], membership: str, body: types.AssignRole) -> Written[types.RoleAssignment]: ...

    @overload
    def assign_to_membership(self: Assignments[Batched], membership: str, body: types.AssignRole) -> Pending[Written[types.RoleAssignment]]: ...

    @operation("assign_membership_role")
    def assign_to_membership(self, membership: str, body: types.AssignRole) -> Any:
        """Assigns one of the membership's tenant's roles."""
        return self._do(Call("POST", path("memberships", membership, "assignments"), json=body, create=True, written=True))

    @overload
    async def assign_global(self: Assignments[Direct], subject: str, body: types.AssignRole) -> Written[types.RoleAssignment]: ...

    @overload
    def assign_global(self: Assignments[Batched], subject: str, body: types.AssignRole) -> Pending[Written[types.RoleAssignment]]: ...

    @operation("assign_global_role")
    def assign_global(self, subject: str, body: types.AssignRole) -> Any:
        """Assigns a global role to a subject directly."""
        return self._do(Call("POST", path("subjects", subject, "global-assignments"), json=body, create=True, written=True))

    @operation("list_global_assignments")
    async def list_global(self: Assignments[Direct], subject: str) -> builtins.list[types.RoleAssignment]:
        response = await self._direct._get(path("subjects", subject, "global-assignments"))
        return cast(builtins.list[types.RoleAssignment], response)

    @overload
    async def unassign(self: Assignments[Direct], id: str) -> Written[types.Deleted]: ...

    @overload
    def unassign(self: Assignments[Batched], id: str) -> Pending[Written[types.Deleted]]: ...

    @operation("unassign")
    def unassign(self, id: str) -> Any:
        return self._do(Call("DELETE", path("assignments", id), written=True))


class Entitlements(_Resource[M]):
    @operation("subject_entitlements")
    async def get(self: Entitlements[Direct], subject: str, *, tenant: str | None = None) -> types.Entitlements:
        """What a subject is entitled to: global only, or in `tenant`."""
        response = await self._direct._get(path("subjects", subject, "entitlements"), {"tenant": tenant})
        return cast(types.Entitlements, response)


class Explain(_Resource[M]):
    @operation("explain_entitlement")
    async def entitlement(self: Explain[Direct], subject: str, *, action: str, tenant: str | None = None) -> types.Explanation:
        """Which assignments and policies bear on `action`, and where it ends
        up granted."""
        params = {"action": action, "tenant": tenant}
        return cast(types.Explanation, await self._direct._get(path("subjects", subject, "explain"), params))

    @operation("explain_decision")
    async def decision(self: Explain[Direct], subject: str, body: types.ExplainDecision) -> types.DecisionExplanation:
        response = await self._direct._post(path("subjects", subject, "explain-decision"), body)
        return cast(types.DecisionExplanation, response)


class Shares(_Resource[M]):
    @operation("list_shares")
    async def list(
        self: Shares[Direct],
        tenant: str,
        *,
        side: types.ShareSide | None = None,
        metadata: MetadataFilter | None = None,
    ) -> types.ShareList:
        params = {"side": side, "metadata": metadata_filter(metadata)}
        response = await self._direct._get(path("tenants", tenant, "shares"), params)
        return cast(types.ShareList, response)

    @operation("get_share")
    async def get(self: Shares[Direct], id: str) -> types.Share:
        return cast(types.Share, await self._direct._get(path("shares", id)))

    @overload
    async def offer(self: Shares[Direct], id: str, body: types.OfferShare) -> Written[types.Share]: ...

    @overload
    def offer(self: Shares[Batched], id: str, body: types.OfferShare) -> Pending[Written[types.Share]]: ...

    @operation("offer_share")
    def offer(self, id: str, body: types.OfferShare) -> Any:
        """Offers a share, or changes its terms, which offers it again. Its
        `metadata` isn't one of its terms: changing only that replaces it
        without offering the share again."""
        return self._do(Call("PUT", path("shares", id), json=body, written=True))

    @overload
    async def accept(self: Shares[Direct], id: str) -> Written[types.Share]: ...

    @overload
    def accept(self: Shares[Batched], id: str) -> Pending[Written[types.Share]]: ...

    @operation("accept_share")
    def accept(self, id: str) -> Any:
        return self._do(Call("POST", path("shares", id, "accept"), written=True))

    @overload
    async def revoke(self: Shares[Direct], id: str, body: types.RevokeShare) -> Written[types.Share]: ...

    @overload
    def revoke(self: Shares[Batched], id: str, body: types.RevokeShare) -> Pending[Written[types.Share]]: ...

    @operation("revoke_share")
    def revoke(self, id: str, body: types.RevokeShare) -> Any:
        return self._do(Call("POST", path("shares", id, "revoke"), json=body, written=True))

    @overload
    async def patch_metadata(
        self: Shares[Direct], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.Share]: ...

    @overload
    def patch_metadata(
        self: Shares[Batched], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.Share]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_share_metadata")
    def patch_metadata(self, id: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("shares", id, "metadata"), json=body, written=True, if_match=if_match))


class RegisteredScopes(_Resource[M]):
    @overload
    async def change(self: RegisteredScopes[Direct], body: types.RegisteredScopeChanges) -> Written[types.RegisteredScopeBatch]: ...

    @overload
    def change(self: RegisteredScopes[Batched], body: types.RegisteredScopeChanges) -> Pending[Written[types.RegisteredScopeBatch]]: ...

    @operation("change_registered_scopes")
    def change(self, body: types.RegisteredScopeChanges) -> Any:
        """Records and removes up to 1000 scopes, all or nothing."""
        return self._do(Call("POST", path("registered-scopes"), json=body, written=True))

    @overload
    async def record(self: RegisteredScopes[Direct], kind: str, id: str, body: types.RecordRegisteredScope) -> Written[types.RegisteredScope]: ...

    @overload
    def record(self: RegisteredScopes[Batched], kind: str, id: str, body: types.RecordRegisteredScope) -> Pending[Written[types.RegisteredScope]]: ...

    @operation("record_registered_scope")
    def record(self, kind: str, id: str, body: types.RecordRegisteredScope) -> Any:
        return self._do(Call("PUT", path("registered-scopes", kind, id), json=body, written=True))

    @overload
    async def remove(self: RegisteredScopes[Direct], kind: str, id: str) -> Written[types.RegisteredScope]: ...

    @overload
    def remove(self: RegisteredScopes[Batched], kind: str, id: str) -> Pending[Written[types.RegisteredScope]]: ...

    @operation("remove_registered_scope")
    def remove(self, kind: str, id: str) -> Any:
        return self._do(Call("DELETE", path("registered-scopes", kind, id), written=True))


class Invites(_Resource[M]):
    @overload
    async def create(self: Invites[Direct], body: types.CreateInvite) -> Written[types.CreatedInvite]: ...

    @overload
    def create(self: Invites[Batched], body: types.CreateInvite) -> Pending[Written[types.CreatedInvite]]: ...

    @operation("create_invite")
    def create(self, body: types.CreateInvite) -> Any:
        """The invite's token is delivered to the address, never returned."""
        return self._do(Call("POST", path("invites"), json=body, create=True, written=True))

    @operation("list_invites")
    async def list(
        self: Invites[Direct],
        *,
        tenant: str | None = None,
        metadata: MetadataFilter | None = None,
        before: str | None = None,
        limit: int | None = None,
    ) -> types.InvitePage:
        """Invites, newest first, optionally only those to `tenant` or whose
        metadata matches, such as `metadata={"tenant_id": "t-1"}`."""
        params = {"tenant": tenant, "metadata": metadata_filter(metadata), "before": before, "limit": limit}
        return cast(types.InvitePage, await self._direct._get(path("invites"), params))

    async def iter(
        self: Invites[Direct],
        *,
        tenant: str | None = None,
        metadata: MetadataFilter | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[types.Invite]:
        """Every matching invite, page after page."""
        params = {"tenant": tenant, "metadata": metadata_filter(metadata), "limit": limit}
        async for invite in self._direct._pages(path("invites"), "invites", params):
            yield cast(types.Invite, invite)

    @operation("get_invite")
    async def get(self: Invites[Direct], id: str) -> types.Invite:
        """The invite's state, without its token."""
        return cast(types.Invite, await self._direct._get(path("invites", id)))

    @overload
    async def revoke(self: Invites[Direct], id: str) -> types.Invite: ...

    @overload
    def revoke(self: Invites[Batched], id: str) -> Pending[types.Invite]: ...

    @operation("revoke_invite")
    def revoke(self, id: str) -> Any:
        """Redeeming it then fails as an expired invite does. A redeemed invite
        can't be revoked."""
        return self._do(Call("POST", path("invites", id, "revoke")))

    @overload
    async def patch_metadata(
        self: Invites[Direct], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.Invite]: ...

    @overload
    def patch_metadata(
        self: Invites[Batched], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.Invite]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_invite_metadata")
    def patch_metadata(self, id: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("invites", id, "metadata"), json=body, written=True, if_match=if_match))


class OidcClients(_Resource[M]):
    @operation("list_oidc_clients")
    async def list(self: OidcClients[Direct], *, metadata: MetadataFilter | None = None) -> builtins.list[types.OidcClient]:
        response = await self._direct._get(path("oidc", "clients"), {"metadata": metadata_filter(metadata)})
        return cast(builtins.list[types.OidcClient], response)

    @operation("get_oidc_client")
    async def get(self: OidcClients[Direct], id: str) -> types.OidcClient:
        return cast(types.OidcClient, await self._direct._get(path("oidc", "clients", id)))

    @overload
    async def put(self: OidcClients[Direct], id: str, body: types.OidcClientDefinition) -> types.OidcClient: ...

    @overload
    def put(self: OidcClients[Batched], id: str, body: types.OidcClientDefinition) -> Pending[types.OidcClient]: ...

    @operation("put_oidc_client")
    def put(self, id: str, body: types.OidcClientDefinition) -> Any:
        """Registers or replaces a client, enabling it if it was disabled."""
        return self._do(Call("PUT", path("oidc", "clients", id), json=body))

    @overload
    async def disable(self: OidcClients[Direct], id: str) -> types.OidcClient: ...

    @overload
    def disable(self: OidcClients[Batched], id: str) -> Pending[types.OidcClient]: ...

    @operation("disable_oidc_client")
    def disable(self, id: str) -> Any:
        return self._do(Call("DELETE", path("oidc", "clients", id)))

    @overload
    async def new_secret(self: OidcClients[Direct], id: str) -> types.OidcClientSecret: ...

    @overload
    def new_secret(self: OidcClients[Batched], id: str) -> Pending[types.OidcClientSecret]: ...

    @operation("new_oidc_client_secret")
    def new_secret(self, id: str) -> Any:
        """The secret is shown only this once; the previous one stops working."""
        return self._do(Call("POST", path("oidc", "clients", id, "secret")))

    @overload
    async def patch_metadata(
        self: OidcClients[Direct], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Written[types.OidcClient]: ...

    @overload
    def patch_metadata(
        self: OidcClients[Batched], id: str, body: dict[str, Any], *, if_match: str | None = None
    ) -> Pending[Written[types.OidcClient]]: ...

    # r[impl metadata.write.patch]
    @operation("patch_oidc_client_metadata")
    def patch_metadata(self, id: str, body: dict[str, Any], *, if_match: str | None = None) -> Any:
        """Merge-patches the metadata (RFC 7396): keys replace the metadata's,
        and `None` removes one. With `if_match`, a `metadata_etag` read
        earlier, only if no one has changed the metadata since; otherwise
        `PreconditionFailed` is raised."""
        return self._do(Call("PATCH", path("oidc", "clients", id, "metadata"), json=body, written=True, if_match=if_match))


class Imports(_Resource[M]):
    """Imports from another system, each all or nothing."""

    @overload
    async def subjects(self: Imports[Direct], body: types.ImportSubjects) -> types.Imported: ...

    @overload
    def subjects(self: Imports[Batched], body: types.ImportSubjects) -> Pending[types.Imported]: ...

    @operation("import_subjects")
    def subjects(self, body: types.ImportSubjects) -> Any:
        return self._do(Call("POST", path("import", "subjects"), json=body))

    @overload
    async def credentials(self: Imports[Direct], body: types.ImportCredentials) -> types.Imported: ...

    @overload
    def credentials(self: Imports[Batched], body: types.ImportCredentials) -> Pending[types.Imported]: ...

    @operation("import_credentials")
    def credentials(self, body: types.ImportCredentials) -> Any:
        return self._do(Call("POST", path("import", "credentials"), json=body))

    @overload
    async def mfa_factors(self: Imports[Direct], body: types.ImportFactors) -> types.Imported: ...

    @overload
    def mfa_factors(self: Imports[Batched], body: types.ImportFactors) -> Pending[types.Imported]: ...

    @operation("import_factors")
    def mfa_factors(self, body: types.ImportFactors) -> Any:
        """TOTP seeds are sent in plaintext and encrypted by Konklav."""
        return self._do(Call("POST", path("import", "mfa-factors"), json=body))

    @overload
    async def sessions(self: Imports[Direct], body: types.ImportSessions) -> types.Imported: ...

    @overload
    def sessions(self: Imports[Batched], body: types.ImportSessions) -> Pending[types.Imported]: ...

    @operation("import_sessions")
    def sessions(self, body: types.ImportSessions) -> Any:
        return self._do(Call("POST", path("import", "sessions"), json=body))


class Batches(_Resource[M]):
    """Several operations in one request, applied all or nothing."""

    @operation("apply_batch")
    async def apply(self: Batches[Direct], body: types.Batch) -> Written[types.BatchResults]:
        """Each operation is given as it would be sent alone; `results` holds
        what each answered. A failure raises the failing operation's error,
        whose `operation` is its position, and nothing is applied."""
        return await self._direct._write("POST", path("batch"), json=body)
