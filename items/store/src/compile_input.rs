//! Loading everything the compiler needs for one subject in one tenant, from
//! one consistent snapshot.

use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_authz::{Assignment, Catalog, Level, Policy, Scope};
use konklav_core::{Cursor, SubjectId, TenantId};

use crate::catalog::{self, CatalogDocument};
use crate::schema::{membership, role, role_assignment, subject, tenant};
use crate::{StoreError, StoreResult, events, roles, shares, templates};

/// (role id, priority, template id, via a membership, scope kind, scope id,
/// role key, assignment id)
type AssignmentRow = (
    uuid::Uuid,
    i32,
    Option<uuid::Uuid>,
    bool,
    Option<String>,
    Option<String>,
    String,
    uuid::Uuid,
);

/// Compiler input plus the revision it reflects.
#[derive(Debug, Clone)]
pub struct CompileInput {
    pub catalog: Catalog,
    pub document: CatalogDocument,
    pub assignments: Vec<Assignment>,
    /// Accepted shares with the tenant, when the subject is an active
    /// member of it.
    pub shares: Vec<konklav_authz::Share>,
    /// The tenant's facts, whatever its state; an empty object without a
    /// tenant.
    pub tenant_facts: serde_json::Value,
    /// The newest event cursor in the snapshot the input was read from.
    pub revision: Cursor,
}

impl CompileInput {
    /// The compiled entitlements, with what shares with the tenant grant.
    #[must_use]
    pub fn compile(&self) -> konklav_authz::Entitlements {
        let mut entitlements = konklav_authz::compile(&self.catalog, &self.assignments);
        entitlements.shared = konklav_authz::shared(&self.catalog, &entitlements, &self.shares);
        entitlements
    }

    /// The catalog's confinements, with the tenant's facts they name.
    #[must_use]
    pub fn confinements(&self) -> konklav_authz::Confinements {
        self.document.confinements(&self.tenant_facts)
    }
}

/// The subject's global assignments and, when `tenant_id` is given, its
/// active membership's assignments in that active tenant.
async fn assignment_rows(
    conn: &mut AsyncPgConnection,
    subject_id: SubjectId,
    tenant_id: Option<TenantId>,
) -> StoreResult<Vec<AssignmentRow>> {
    let mut rows: Vec<AssignmentRow> = role_assignment::table
        .inner_join(role::table)
        .filter(role_assignment::subject_id.eq(subject_id.as_uuid()))
        .select((
            role::id,
            role::priority,
            role::template_id,
            diesel::dsl::sql::<diesel::sql_types::Bool>("false"),
            role_assignment::scope_kind,
            role_assignment::scope_id,
            role::key,
            role_assignment::id,
        ))
        .load(conn)
        .await?;
    if let Some(tenant_id) = tenant_id {
        let membership_rows = role_assignment::table
            .inner_join(role::table)
            .inner_join(membership::table.inner_join(tenant::table))
            .filter(membership::subject_id.eq(subject_id.as_uuid()))
            .filter(membership::tenant_id.eq(tenant_id.as_uuid()))
            .filter(membership::state.eq("active"))
            .filter(tenant::state.eq("active"))
            .select((
                role::id,
                role::priority,
                role::template_id,
                diesel::dsl::sql::<diesel::sql_types::Bool>("true"),
                role_assignment::scope_kind,
                role_assignment::scope_id,
                role::key,
                role_assignment::id,
            ))
            .load::<AssignmentRow>(conn)
            .await?;
        rows.extend(membership_rows);
    }
    Ok(rows)
}

/// The accepted shares with `tenant`, when `subject` is an active member
/// of it; none otherwise.
async fn shares_for_member(
    conn: &mut AsyncPgConnection,
    subject_id: SubjectId,
    tenant_id: Option<TenantId>,
) -> StoreResult<Vec<konklav_authz::Share>> {
    let Some(tenant_id) = tenant_id else {
        return Ok(Vec::new());
    };
    let member = membership::table
        .inner_join(tenant::table)
        .filter(membership::subject_id.eq(subject_id.as_uuid()))
        .filter(membership::tenant_id.eq(tenant_id.as_uuid()))
        .filter(membership::state.eq("active"))
        .filter(tenant::state.eq("active"))
        .count()
        .get_result::<i64>(conn)
        .await?
        > 0;
    if member {
        shares::accepted_for(conn, tenant_id).await
    } else {
        Ok(Vec::new())
    }
}

/// Loads the active assignments of `subject`: its global assignments and,
/// when `tenant` is given, its membership's assignments there. Disabled
/// subjects, ended memberships and inactive tenants contribute nothing.
///
/// Reads run in one repeatable-read transaction so the revision matches
/// the data, or, inside a transaction already, in that one, which then
/// sees its own uncommitted writes.
// r[impl authz.compile.inactive]
// r[impl authz.compile.revision]
// r[impl item.store.compile-snapshot]
pub async fn load(
    conn: &mut AsyncPgConnection,
    subject_id: SubjectId,
    tenant_id: Option<TenantId>,
) -> StoreResult<CompileInput> {
    if crate::in_transaction(conn) {
        return read(conn, subject_id, tenant_id).await;
    }
    conn.build_transaction()
        .read_only()
        .repeatable_read()
        .run::<_, StoreError, _>(async |conn| read(conn, subject_id, tenant_id).await)
        .await
}

/// [`load`] inside a transaction the caller runs, such as one that reads
/// the past through [`crate::history::shadow`]. The revision is the
/// newest event cursor, which history doesn't version.
pub async fn read(
    conn: &mut AsyncPgConnection,
    subject_id: SubjectId,
    tenant_id: Option<TenantId>,
) -> StoreResult<CompileInput> {
    let revision = events::head(conn).await?;
    let document = catalog::load(conn).await?;
    let catalog = document.compile_catalog();
    let tenant_facts = match tenant_id {
        Some(tenant_id) => tenant::table
            .find(tenant_id.as_uuid())
            .select(tenant::facts)
            .first::<serde_json::Value>(conn)
            .await
            .optional()?
            .unwrap_or_default(),
        None => serde_json::Value::Object(serde_json::Map::new()),
    };
    let active = subject::table
        .find(subject_id.as_uuid())
        .select(subject::state)
        .first::<String>(conn)
        .await
        .optional()?
        .is_some_and(|state| state == "active");
    if !active {
        return Ok(CompileInput {
            catalog,
            document,
            assignments: Vec::new(),
            shares: Vec::new(),
            tenant_facts,
            revision,
        });
    }

    let rows = assignment_rows(conn, subject_id, tenant_id).await?;
    let shares = shares_for_member(conn, subject_id, tenant_id).await?;

    let role_ids: Vec<uuid::Uuid> = rows.iter().map(|row| row.0).collect();
    let template_ids: Vec<uuid::Uuid> = rows.iter().filter_map(|row| row.2).collect();
    let role_policies = roles::policies_of(conn, &role_ids).await?;
    let template_policies = templates::policies_of(conn, &template_ids).await?;
    let policies_for = |policies: &[(uuid::Uuid, Policy)], id: uuid::Uuid| -> Vec<Policy> {
        policies
            .iter()
            .filter(|(owner, _)| *owner == id)
            .map(|(_, policy)| policy.clone())
            .collect()
    };
    let assignments = rows
        .into_iter()
        .map(
            |(role_id, priority, template_id, in_tenant, scope_kind, scope_id, key, id)| {
                Assignment {
                    label: format!("{key} ({id})"),
                    level: match (in_tenant, scope_kind.zip(scope_id)) {
                        (false, _) => Level::Global,
                        (true, None) => Level::Tenant,
                        (true, Some((kind, id))) => Level::Scope(Scope { kind, id }),
                    },
                    priority,
                    template_policies: template_id
                        .map(|id| policies_for(&template_policies, id))
                        .unwrap_or_default(),
                    role_policies: policies_for(&role_policies, role_id),
                }
            },
        )
        .collect();
    Ok(CompileInput {
        catalog,
        document,
        assignments,
        shares,
        tenant_facts,
        revision,
    })
}
