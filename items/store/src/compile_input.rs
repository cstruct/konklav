//! Loading everything the compiler needs for one subject in one tenant, from
//! one consistent snapshot.

use conclave_authz::{Assignment, Catalog, Level, Policy, Scope};
use conclave_core::{Cursor, SubjectId, TenantId};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::catalog::{self, CatalogDocument};
use crate::schema::{membership, role, role_assignment, subject, tenant};
use crate::{StoreError, StoreResult, events, roles, templates};

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
    /// The newest event cursor in the snapshot the input was read from.
    pub revision: Cursor,
}

/// Loads the active assignments of `subject`: its global assignments and,
/// when `tenant` is given, its membership's assignments there. Disabled
/// subjects, ended memberships and inactive tenants contribute nothing.
///
/// Reads run in one repeatable-read transaction so the revision matches
/// the data.
// r[impl authz.compile.inactive]
// r[impl authz.compile.revision]
pub async fn load(
    conn: &mut AsyncPgConnection,
    subject_id: SubjectId,
    tenant_id: Option<TenantId>,
) -> StoreResult<CompileInput> {
    conn.build_transaction()
        .read_only()
        .repeatable_read()
        .run::<_, StoreError, _>(async |conn| {
            let revision = events::head(conn).await?;
            let document = catalog::load(conn).await?;
            let catalog = document.compile_catalog();
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
                    revision,
                });
            }

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
                revision,
            })
        })
        .await
}
