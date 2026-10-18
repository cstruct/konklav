//! Roles (tenant-local, or global when owned by the root tenant) and role
//! assignments.

use chrono::{DateTime, Utc};
use konklav_authz::{Policy, Scope};
use konklav_core::{MembershipId, SubjectId, TenantId};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde::Serialize;

use crate::schema::{role, role_assignment, role_policy, template};
use crate::templates::{effect_str, parse_effect};
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Role {
    pub id: uuid::Uuid,
    pub tenant_id: TenantId,
    pub key: String,
    /// The key of the template the role derives from.
    pub template: Option<String>,
    pub priority: i32,
    pub metadata: serde_json::Value,
    /// The role's own policies, which override its template's.
    pub policies: Vec<Policy>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

type Row = (
    uuid::Uuid,
    uuid::Uuid,
    String,
    Option<String>,
    i32,
    serde_json::Value,
    DateTime<Utc>,
    DateTime<Utc>,
);

pub(crate) async fn policies_of(
    conn: &mut AsyncPgConnection,
    ids: &[uuid::Uuid],
) -> QueryResult<Vec<(uuid::Uuid, Policy)>> {
    Ok(role_policy::table
        .filter(role_policy::role_id.eq_any(ids))
        .order((role_policy::role_id, role_policy::action))
        .select((
            role_policy::role_id,
            role_policy::action,
            role_policy::effect,
            role_policy::scope_bound,
        ))
        .load::<(uuid::Uuid, String, String, bool)>(conn)
        .await?
        .into_iter()
        .map(|(id, action, effect, scope_bound)| {
            (
                id,
                Policy {
                    action,
                    effect: parse_effect(&effect),
                    scope_bound,
                },
            )
        })
        .collect())
}

async fn load(
    conn: &mut AsyncPgConnection,
    query: role::BoxedQuery<'_, diesel::pg::Pg>,
) -> StoreResult<Vec<Role>> {
    let rows = query
        .left_join(template::table)
        .select((
            role::id,
            role::tenant_id,
            role::key,
            template::key.nullable(),
            role::priority,
            role::metadata,
            role::created_at,
            role::updated_at,
        ))
        .order(role::key.asc())
        .load::<Row>(conn)
        .await?;
    let ids: Vec<uuid::Uuid> = rows.iter().map(|row| row.0).collect();
    let policies = policies_of(conn, &ids).await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, tenant_id, key, template, priority, metadata, created_at, updated_at)| Role {
                id,
                tenant_id: tenant_id.into(),
                key,
                template,
                priority,
                metadata,
                policies: policies
                    .iter()
                    .filter(|(role, _)| *role == id)
                    .map(|(_, policy)| policy.clone())
                    .collect(),
                created_at,
                updated_at,
            },
        )
        .collect())
}

pub async fn get(conn: &mut AsyncPgConnection, tenant: TenantId, key: &str) -> StoreResult<Role> {
    let query = role::table
        .filter(role::tenant_id.eq(uuid::Uuid::from(tenant)))
        .filter(role::key.eq(key.to_owned()))
        .into_boxed();
    load(conn, query).await?.pop().ok_or(StoreError::NotFound)
}

pub async fn list(conn: &mut AsyncPgConnection, tenant: TenantId) -> StoreResult<Vec<Role>> {
    let query = role::table
        .filter(role::tenant_id.eq(uuid::Uuid::from(tenant)))
        .into_boxed();
    load(conn, query).await
}

/// What a role should look like.
#[derive(Debug, Clone)]
pub struct RoleDefinition {
    pub template: Option<String>,
    pub priority: i32,
    /// An object, opaque to Conclave.
    pub metadata: serde_json::Value,
    pub policies: Vec<Policy>,
}

impl Default for RoleDefinition {
    fn default() -> Self {
        Self {
            template: None,
            priority: 0,
            metadata: serde_json::json!({}),
            policies: Vec::new(),
        }
    }
}

/// Creates or replaces the role `key` in `tenant`, including its own
/// policies.
// r[impl authz.role.tenant-local]
// r[impl authz.role.priority]
pub async fn put(
    conn: &mut AsyncPgConnection,
    tenant: TenantId,
    key: &str,
    definition: &RoleDefinition,
) -> StoreResult<Role> {
    conn.transaction::<_, StoreError, _>(async |conn| {
        let template_id = match &definition.template {
            Some(template_key) => Some(
                template::table
                    .filter(template::key.eq(template_key))
                    .select(template::id)
                    .first::<uuid::Uuid>(conn)
                    .await
                    .optional()?
                    .ok_or_else(|| {
                        StoreError::Conflict(format!("template `{template_key}` does not exist"))
                    })?,
            ),
            None => None,
        };
        let id = diesel::insert_into(role::table)
            .values((
                role::id.eq(uuid::Uuid::now_v7()),
                role::tenant_id.eq(tenant.as_uuid()),
                role::key.eq(key),
                role::template_id.eq(template_id),
                role::priority.eq(definition.priority),
                role::metadata.eq(&definition.metadata),
            ))
            .on_conflict((role::tenant_id, role::key))
            .do_update()
            .set((
                role::template_id.eq(template_id),
                role::priority.eq(definition.priority),
                role::metadata.eq(&definition.metadata),
                role::updated_at.eq(diesel::dsl::now),
            ))
            .returning(role::id)
            .get_result::<uuid::Uuid>(conn)
            .await
            .map_err(StoreError::from_constraint)?;
        diesel::delete(role_policy::table.filter(role_policy::role_id.eq(id)))
            .execute(conn)
            .await?;
        for policy in &definition.policies {
            diesel::insert_into(role_policy::table)
                .values((
                    role_policy::role_id.eq(id),
                    role_policy::action.eq(&policy.action),
                    role_policy::effect.eq(effect_str(policy.effect)),
                    role_policy::scope_bound.eq(policy.scope_bound),
                ))
                .execute(conn)
                .await
                .map_err(StoreError::from_constraint)?;
        }
        get(conn, tenant, key).await
    })
    .await
}

/// Creates one role per template in `tenant`, keyed like the template.
/// Existing roles with those keys are left as they are.
// r[impl authz.role.instantiate]
pub async fn instantiate(
    conn: &mut AsyncPgConnection,
    tenant: TenantId,
    templates: &[String],
) -> StoreResult<()> {
    for key in templates {
        if get(conn, tenant, key).await.is_ok() {
            continue;
        }
        let definition = RoleDefinition {
            template: Some(key.clone()),
            ..RoleDefinition::default()
        };
        put(conn, tenant, key, &definition).await?;
    }
    Ok(())
}

/// Deletes a role and, with it, its assignments. Returns whether it existed.
pub async fn delete(
    conn: &mut AsyncPgConnection,
    tenant: TenantId,
    key: &str,
) -> StoreResult<bool> {
    let deleted = diesel::delete(
        role::table
            .filter(role::tenant_id.eq(tenant.as_uuid()))
            .filter(role::key.eq(key)),
    )
    .execute(conn)
    .await?;
    Ok(deleted > 0)
}

/// Who a role is assigned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "id")]
pub enum AssignmentTarget {
    /// A tenant role, for a membership in the role's tenant.
    Membership(MembershipId),
    /// A global role, for a subject directly.
    Subject(SubjectId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleAssignment {
    pub id: uuid::Uuid,
    pub role_id: uuid::Uuid,
    pub target: AssignmentTarget,
    pub scope: Option<Scope>,
    /// The identity provider whose claim mapping created it, if any.
    pub managed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

type AssignmentRow = (
    uuid::Uuid,
    uuid::Uuid,
    Option<uuid::Uuid>,
    Option<uuid::Uuid>,
    Option<String>,
    Option<String>,
    DateTime<Utc>,
    Option<String>,
);

fn assignment_columns() -> (
    role_assignment::id,
    role_assignment::role_id,
    role_assignment::membership_id,
    role_assignment::subject_id,
    role_assignment::scope_kind,
    role_assignment::scope_id,
    role_assignment::created_at,
    role_assignment::managed_by,
) {
    (
        role_assignment::id,
        role_assignment::role_id,
        role_assignment::membership_id,
        role_assignment::subject_id,
        role_assignment::scope_kind,
        role_assignment::scope_id,
        role_assignment::created_at,
        role_assignment::managed_by,
    )
}

fn to_assignment(row: AssignmentRow) -> RoleAssignment {
    let (id, role_id, membership, subject, scope_kind, scope_id, created_at, managed_by) = row;
    let target = match (membership, subject) {
        (Some(membership), _) => AssignmentTarget::Membership(membership.into()),
        (None, Some(subject)) => AssignmentTarget::Subject(subject.into()),
        (None, None) => unreachable!("role_assignment_target check"),
    };
    RoleAssignment {
        id,
        role_id,
        target,
        scope: scope_kind
            .zip(scope_id)
            .map(|(kind, id)| Scope { kind, id }),
        managed_by,
        created_at,
    }
}

/// Assigns a role. Assigning the same role to the same target and scope
/// again returns the existing assignment.
// r[impl authz.assignment.membership]
// r[impl authz.assignment.global]
// r[impl authz.assignment.multiple]
// r[impl authz.assignment.scope-kind]
pub async fn assign(
    conn: &mut AsyncPgConnection,
    role_id: uuid::Uuid,
    target: AssignmentTarget,
    scope: Option<&Scope>,
) -> StoreResult<RoleAssignment> {
    assign_managed(conn, role_id, target, scope, None).await
}

/// [`assign`], recording the identity provider whose claim mapping asked
/// for it. An existing equal assignment keeps whoever made it.
pub async fn assign_managed(
    conn: &mut AsyncPgConnection,
    role_id: uuid::Uuid,
    target: AssignmentTarget,
    scope: Option<&Scope>,
    managed_by: Option<&str>,
) -> StoreResult<RoleAssignment> {
    let (membership, subject) = match target {
        AssignmentTarget::Membership(id) => (Some(uuid::Uuid::from(id)), None),
        AssignmentTarget::Subject(id) => (None, Some(uuid::Uuid::from(id))),
    };
    let scope_kind = scope.map(|s| s.kind.clone());
    let scope_id = scope.map(|s| s.id.clone());
    diesel::insert_into(role_assignment::table)
        .values((
            role_assignment::id.eq(uuid::Uuid::now_v7()),
            role_assignment::role_id.eq(role_id),
            role_assignment::membership_id.eq(membership),
            role_assignment::subject_id.eq(subject),
            role_assignment::scope_kind.eq(&scope_kind),
            role_assignment::scope_id.eq(&scope_id),
            role_assignment::managed_by.eq(managed_by),
        ))
        .on_conflict_do_nothing()
        .execute(conn)
        .await
        .map_err(StoreError::from_constraint)?;
    role_assignment::table
        .filter(role_assignment::role_id.eq(role_id))
        .filter(role_assignment::membership_id.is_not_distinct_from(membership))
        .filter(role_assignment::subject_id.is_not_distinct_from(subject))
        .filter(role_assignment::scope_kind.is_not_distinct_from(&scope_kind))
        .filter(role_assignment::scope_id.is_not_distinct_from(&scope_id))
        .select(assignment_columns())
        .first::<AssignmentRow>(conn)
        .await
        .map(to_assignment)
        .map_err(StoreError::from)
}

/// Removes an assignment. Returns whether it existed.
pub async fn unassign(conn: &mut AsyncPgConnection, id: uuid::Uuid) -> StoreResult<bool> {
    let deleted = diesel::delete(role_assignment::table.find(id))
        .execute(conn)
        .await?;
    Ok(deleted > 0)
}

pub async fn assignments_of_membership(
    conn: &mut AsyncPgConnection,
    membership: MembershipId,
) -> StoreResult<Vec<RoleAssignment>> {
    Ok(role_assignment::table
        .filter(role_assignment::membership_id.eq(membership.as_uuid()))
        .order(role_assignment::created_at.asc())
        .select(assignment_columns())
        .load::<AssignmentRow>(conn)
        .await?
        .into_iter()
        .map(to_assignment)
        .collect())
}

pub async fn global_assignments_of(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
) -> StoreResult<Vec<RoleAssignment>> {
    Ok(role_assignment::table
        .filter(role_assignment::subject_id.eq(subject.as_uuid()))
        .order(role_assignment::created_at.asc())
        .select(assignment_columns())
        .load::<AssignmentRow>(conn)
        .await?
        .into_iter()
        .map(to_assignment)
        .collect())
}

/// Every assignment `provider` manages for `subject`: global ones, and those
/// of the subject's memberships.
pub async fn managed_assignments_of(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
    provider: &str,
) -> StoreResult<Vec<RoleAssignment>> {
    use crate::schema::membership;
    let memberships = membership::table
        .filter(membership::subject_id.eq(subject.as_uuid()))
        .select(membership::id);
    Ok(role_assignment::table
        .filter(role_assignment::managed_by.eq(provider))
        .filter(
            role_assignment::subject_id
                .eq(subject.as_uuid())
                .or(role_assignment::membership_id.eq_any(memberships.nullable())),
        )
        .select(assignment_columns())
        .load::<AssignmentRow>(conn)
        .await?
        .into_iter()
        .map(to_assignment)
        .collect())
}
