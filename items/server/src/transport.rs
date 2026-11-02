//! Conversions from storage models to `konklav-api`'s transport types, at
//! the boundary of the control-plane surface.

use konklav_api as api;
use konklav_store::memberships::{Membership, MembershipState};
use konklav_store::roles::{AssignmentTarget, RoleAssignment};
use konklav_store::tenants::{Tenant, TenantState};

pub(crate) fn tenant(tenant: Tenant) -> api::Tenant {
    api::Tenant {
        id: tenant.id,
        parent_id: tenant.parent_id,
        state: tenant_state(tenant.state),
        facts: tenant.facts,
        created_at: tenant.created_at,
        updated_at: tenant.updated_at,
    }
}

pub(crate) fn tenant_state(state: TenantState) -> api::TenantState {
    match state {
        TenantState::Active => api::TenantState::Active,
        TenantState::Suspended => api::TenantState::Suspended,
        TenantState::Deleted => api::TenantState::Deleted,
    }
}

pub(crate) fn store_tenant_state(state: api::TenantState) -> TenantState {
    match state {
        api::TenantState::Active => TenantState::Active,
        api::TenantState::Suspended => TenantState::Suspended,
        api::TenantState::Deleted => TenantState::Deleted,
    }
}

pub(crate) fn membership(membership: Membership) -> api::Membership {
    api::Membership {
        id: membership.id,
        subject_id: membership.subject_id,
        tenant_id: membership.tenant_id,
        state: match membership.state {
            MembershipState::Active => api::MembershipState::Active,
            MembershipState::Ended => api::MembershipState::Ended,
        },
        facts: membership.facts,
        managed_by: membership.managed_by,
        created_at: membership.created_at,
        updated_at: membership.updated_at,
    }
}

pub(crate) fn role_assignment(assignment: RoleAssignment) -> api::RoleAssignment {
    api::RoleAssignment {
        id: assignment.id,
        role_id: assignment.role_id,
        target: match assignment.target {
            AssignmentTarget::Membership(id) => api::AssignmentTarget::Membership(id),
            AssignmentTarget::Subject(id) => api::AssignmentTarget::Subject(id),
        },
        scope: assignment.scope.map(|scope| api::Scope {
            kind: scope.kind,
            id: scope.id,
        }),
        managed_by: assignment.managed_by,
        created_at: assignment.created_at,
    }
}
