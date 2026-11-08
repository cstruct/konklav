//! Memberships: a subject's presence in a tenant.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::{MembershipId, SubjectId, TenantId};
use serde::{Deserialize, Serialize};

use crate::schema::membership;
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Active,
    Ended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Membership {
    pub id: MembershipId,
    pub subject_id: SubjectId,
    pub tenant_id: TenantId,
    pub state: MembershipState,
    pub facts: serde_json::Value,
    pub metadata: serde_json::Value,
    /// The identity provider whose claim mapping created it, if any.
    pub managed_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Membership {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == MembershipState::Active
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = membership)]
struct Row {
    id: uuid::Uuid,
    subject_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    state: String,
    facts: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    managed_by: Option<String>,
    metadata: serde_json::Value,
}

impl From<Row> for Membership {
    fn from(row: Row) -> Self {
        Self {
            id: row.id.into(),
            subject_id: row.subject_id.into(),
            tenant_id: row.tenant_id.into(),
            state: if row.state == "ended" {
                MembershipState::Ended
            } else {
                MembershipState::Active
            },
            facts: row.facts,
            metadata: row.metadata,
            managed_by: row.managed_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

pub async fn get(conn: &mut AsyncPgConnection, id: MembershipId) -> StoreResult<Membership> {
    membership::table
        .find(id.as_uuid())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Membership::from)
        .ok_or(StoreError::NotFound)
}

/// The subject's active membership in `tenant`, if any.
pub async fn find_active(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
    tenant: TenantId,
) -> StoreResult<Option<Membership>> {
    Ok(membership::table
        .filter(membership::subject_id.eq(subject.as_uuid()))
        .filter(membership::tenant_id.eq(tenant.as_uuid()))
        .filter(membership::state.eq("active"))
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Membership::from))
}

/// Creates a membership with a caller-supplied id. Repeating the call for
/// the same subject and tenant returns the existing membership; anything
/// else reusing the id, or a second active membership of the subject in the
/// tenant, is a conflict.
// r[impl membership.first-class]
// r[impl membership.unique]
pub async fn create(
    conn: &mut AsyncPgConnection,
    id: MembershipId,
    subject: SubjectId,
    tenant: TenantId,
    facts: &serde_json::Value,
) -> StoreResult<(Membership, bool)> {
    create_managed(conn, id, subject, tenant, facts, None).await
}

/// [`create`] with metadata, which a repeat must match.
// r[impl metadata.write.create]
pub async fn create_with_metadata(
    conn: &mut AsyncPgConnection,
    id: MembershipId,
    subject: SubjectId,
    tenant: TenantId,
    facts: &serde_json::Value,
    metadata: &serde_json::Value,
) -> StoreResult<(Membership, bool)> {
    insert(conn, id, subject, tenant, facts, metadata, None).await
}

/// [`create`], recording the identity provider whose claim mapping asked
/// for the membership.
pub async fn create_managed(
    conn: &mut AsyncPgConnection,
    id: MembershipId,
    subject: SubjectId,
    tenant: TenantId,
    facts: &serde_json::Value,
    managed_by: Option<&str>,
) -> StoreResult<(Membership, bool)> {
    let metadata = crate::metadata::empty();
    insert(conn, id, subject, tenant, facts, &metadata, managed_by).await
}

async fn insert(
    conn: &mut AsyncPgConnection,
    id: MembershipId,
    subject: SubjectId,
    tenant: TenantId,
    facts: &serde_json::Value,
    metadata: &serde_json::Value,
    managed_by: Option<&str>,
) -> StoreResult<(Membership, bool)> {
    let inserted = diesel::insert_into(membership::table)
        .values((
            membership::id.eq(id.as_uuid()),
            membership::subject_id.eq(subject.as_uuid()),
            membership::tenant_id.eq(tenant.as_uuid()),
            membership::facts.eq(facts),
            membership::managed_by.eq(managed_by),
            membership::metadata.eq(metadata),
        ))
        .on_conflict(membership::id)
        .do_nothing()
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .optional()
        .map_err(|error| {
            StoreError::from_unique_violation(
                error,
                "an active membership of this subject in this tenant",
            )
        })?;
    if let Some(row) = inserted {
        return Ok((row.into(), true));
    }
    let existing = get(conn, id).await?;
    if existing.subject_id != subject || existing.tenant_id != tenant {
        Err(StoreError::Conflict(format!(
            "membership {id} already exists for another subject or tenant"
        )))
    } else if existing.metadata != *metadata {
        Err(StoreError::Conflict(format!(
            "membership {id} already exists with other metadata"
        )))
    } else {
        Ok((existing, false))
    }
}

/// Ends a membership. Returns whether it was active.
// r[impl membership.state]
pub async fn end(conn: &mut AsyncPgConnection, id: MembershipId) -> StoreResult<bool> {
    let updated = diesel::update(membership::table.find(id.as_uuid()))
        .filter(membership::state.eq("active"))
        .set((
            membership::state.eq("ended"),
            membership::updated_at.eq(diesel::dsl::now),
        ))
        .execute(conn)
        .await?;
    if updated == 0 {
        get(conn, id).await?;
    }
    Ok(updated > 0)
}

pub async fn set_facts(
    conn: &mut AsyncPgConnection,
    id: MembershipId,
    facts: &serde_json::Value,
) -> StoreResult<Membership> {
    diesel::update(membership::table.find(id.as_uuid()))
        .set((
            membership::facts.eq(facts),
            membership::updated_at.eq(diesel::dsl::now),
        ))
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .optional()?
        .map(Membership::from)
        .ok_or(StoreError::NotFound)
}

pub async fn list_for_subject(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
) -> StoreResult<Vec<Membership>> {
    Ok(membership::table
        .filter(membership::subject_id.eq(subject.as_uuid()))
        .order(membership::created_at.asc())
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(Membership::from)
        .collect())
}

/// A tenant's memberships, oldest first, optionally only active ones or
/// those whose metadata contains `metadata`.
// r[impl metadata.filter]
pub async fn list_for_tenant(
    conn: &mut AsyncPgConnection,
    tenant: TenantId,
    active_only: bool,
    metadata: Option<&serde_json::Value>,
) -> StoreResult<Vec<Membership>> {
    let mut query = membership::table
        .filter(membership::tenant_id.eq(tenant.as_uuid()))
        .into_boxed();
    if let Some(metadata) = metadata {
        query = query.filter(membership::metadata.contains(metadata.clone()));
    }
    if active_only {
        query = query.filter(membership::state.eq("active"));
    }
    Ok(query
        .order(membership::created_at.asc())
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(Membership::from)
        .collect())
}

/// The subject's active memberships that `provider` manages.
pub async fn list_managed(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
    provider: &str,
) -> StoreResult<Vec<Membership>> {
    Ok(membership::table
        .filter(membership::subject_id.eq(subject.as_uuid()))
        .filter(membership::managed_by.eq(provider))
        .filter(membership::state.eq("active"))
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(Membership::from)
        .collect())
}
