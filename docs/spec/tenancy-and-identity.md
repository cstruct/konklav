# Tenancy And Identity

This file establishes the requirements for tenant topology, memberships, delegated tenant administration, and identity subjects.

## Tenants

r[tenant.namespace.isolation]
Every tenant MUST have an explicit namespace boundary so identities, memberships, roles, and policy assignments can be isolated by default.

r[tenant.lifecycle.state-machine]
Tenant creation, suspension, and deletion MUST follow an explicit lifecycle model so administrative behavior is auditable and reversible where possible.

r[tenant.root.bootstrap]
The platform MUST always materialize a root tenant with the reserved identifier `root` before runtime tenant provisioning begins, even when the managed tenant list omits an explicit root entry.

r[tenant.root.managed-entry]
If managed tenant configuration includes the root tenant, the platform MUST treat that entry as configuration for the pre-existing bootstrap root tenant rather than as creation of an additional tenant.

r[tenant.tree.parent-reference]
Every non-root tenant MUST record exactly one parent tenant reference so delegated administration can be modeled explicitly without collapsing tenant boundaries.

r[tenant.tree.root-default-parent]
The baseline tenant provisioning model MUST support creating direct child tenants beneath the bootstrap root tenant.

r[tenant.admin.no-implicit-child-access]
A parent-child tenant relationship MUST NOT by itself grant direct access to child tenant resources without an explicit delegated assumption flow or child-tenant policy grant.

## Subjects and memberships

r[user.membership.tenant-binding]
Tenant memberships MUST bind a subject to a tenant through a first-class membership record rather than relying on implicit global user state.

r[user.profile.externalized-attributes]
Tenant-member profile attributes MUST distinguish between locally managed data and data materialized from upstream identity providers.

r[user.assumption.delegated-principal]
Cross-tenant role assumption MUST preserve the originating subject and tenant as delegated actor context rather than collapsing multiple operators into a shared synthetic child-tenant user identity.

## Identities

r[identity.subject.global-identifier]
Every identity subject MUST have a stable internal identifier that survives username changes, email changes, and upstream provider remaps.

r[identity.subject.linked-credentials]
An identity subject MUST be able to link multiple credential or federation sources to the same internal subject record.

r[identity.subject.linked-credentials.versioned-history]
Linked subject credentials MUST preserve temporal history so replacement, revocation, and recovery remain auditable rather than overwriting prior credential state in place.

r[identity.subject.invite-redeem]
The platform MUST support issuing a subject invite and redeeming it into a linked credential without requiring a provider-specific email delivery implementation.

r[identity.subject.invite.audit-history]
Issued subject invites MUST preserve auditable issue, expiry, and redemption state across control-plane restarts.
