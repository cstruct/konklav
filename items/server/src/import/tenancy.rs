//! Tenancy and authorization records: the catalog, templates, tenants,
//! memberships and role assignments. The control-plane endpoints write
//! through these too, so both apply the same checks. Callers authorize and
//! open the transaction.

use konklav_authz::{Policy, Scope};
use konklav_core::{MembershipId, SubjectId, TenantId};
use konklav_store::catalog::{self, CatalogDocument, FactTarget};
use konklav_store::memberships::{self, Membership};
use konklav_store::roles::{self, AssignmentTarget, RoleAssignment};
use konklav_store::templates::{self, Template};
use konklav_store::tenants::{self, Tenant, TenantState};
use konklav_store::{Connection, StoreError, subjects};

use crate::error::{ApiError, ErrorCode};

/// Maps a missing record to a not-found error naming `what`.
pub(crate) fn not_found_as(what: &'static str) -> impl Fn(StoreError) -> ApiError {
    move |error| match error {
        StoreError::NotFound => ApiError::not_found(what),
        other => other.into(),
    }
}

/// Checks facts against the stored catalog's declarations for `target`.
pub(crate) async fn validate_facts(
    conn: &mut Connection,
    target: FactTarget,
    facts: &serde_json::Value,
) -> Result<(), ApiError> {
    let document = catalog::load(conn).await?;
    document
        .validate_facts(target, facts)
        .map_err(ApiError::invalid_request)
}

/// Replaces the whole catalog with a valid document.
pub(crate) async fn replace_catalog(
    conn: &mut Connection,
    document: &CatalogDocument,
) -> Result<(), ApiError> {
    document.validate().map_err(ApiError::invalid_request)?;
    catalog::replace(conn, document).await?;
    Ok(())
}

/// Creates or replaces a template.
pub(crate) async fn put_template(
    conn: &mut Connection,
    key: &str,
    description: &str,
    metadata: &serde_json::Value,
    policies: &[Policy],
) -> Result<Template, ApiError> {
    Ok(templates::put(conn, key, description, metadata, policies).await?)
}

/// Creates a tenant unless one with its id exists, instantiating roles from
/// `templates` when it is new. Returns whether it was created.
pub(crate) async fn create_tenant(
    conn: &mut Connection,
    id: TenantId,
    parent: TenantId,
    facts: &serde_json::Value,
    templates: &[String],
) -> Result<(Tenant, bool), ApiError> {
    validate_facts(conn, FactTarget::Tenant, facts).await?;
    let (tenant, created) = tenants::create(conn, id, parent, facts).await?;
    if created {
        roles::instantiate(conn, id, templates).await?;
    }
    Ok((tenant, created))
}

/// Creates a membership unless one with its id exists. Returns whether it
/// was created.
pub(crate) async fn create_membership(
    conn: &mut Connection,
    id: MembershipId,
    subject: SubjectId,
    tenant: TenantId,
    facts: &serde_json::Value,
) -> Result<(Membership, bool), ApiError> {
    subjects::get(conn, subject)
        .await
        .map_err(not_found_as("subject"))?;
    let target = tenants::get(conn, tenant)
        .await
        .map_err(not_found_as("tenant"))?;
    if target.state == TenantState::Deleted {
        return Err(ApiError::new(ErrorCode::Conflict, "the tenant is deleted"));
    }
    validate_facts(conn, FactTarget::Membership, facts).await?;
    Ok(memberships::create(conn, id, subject, tenant, facts).await?)
}

/// Assigns the role `key` of the membership's tenant to the membership.
/// An equal existing assignment is kept.
pub(crate) async fn assign_membership_role(
    conn: &mut Connection,
    membership: MembershipId,
    key: &str,
    scope: Option<&Scope>,
) -> Result<RoleAssignment, ApiError> {
    let found = memberships::get(conn, membership)
        .await
        .map_err(not_found_as("membership"))?;
    let role = roles::get(conn, found.tenant_id, key)
        .await
        .map_err(not_found_as("role"))?;
    Ok(roles::assign(
        conn,
        role.id,
        AssignmentTarget::Membership(membership),
        scope,
    )
    .await?)
}

/// Assigns the global role `key` to a subject. An equal existing assignment
/// is kept.
pub(crate) async fn assign_global_role(
    conn: &mut Connection,
    subject: SubjectId,
    role: &roles::Role,
) -> Result<RoleAssignment, ApiError> {
    subjects::get(conn, subject)
        .await
        .map_err(not_found_as("subject"))?;
    Ok(roles::assign(conn, role.id, AssignmentTarget::Subject(subject), None).await?)
}
