//! Tenants. Konklav is the source of truth for whether a tenant exists, its
//! parent and its lifecycle state.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::TenantId;
use serde::{Deserialize, Serialize};

use crate::schema::tenant;
use crate::{StoreError, StoreResult};

/// The root tenant: the nil UUID, addressed as `root` in APIs.
// r[impl tenant.root.bootstrap]
pub const ROOT: TenantId = TenantId::from_uuid(uuid::Uuid::nil());

/// Parses a tenant reference: a UUID or `root`.
#[must_use]
pub fn parse_reference(value: &str) -> Option<TenantId> {
    if value == "root" {
        Some(ROOT)
    } else {
        value.parse().ok()
    }
}

// r[impl tenant.lifecycle.states]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    Active,
    Suspended,
    Deleted,
}

impl TenantState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "suspended" => Self::Suspended,
            "deleted" => Self::Deleted,
            _ => Self::Active,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tenant {
    pub id: TenantId,
    pub parent_id: Option<TenantId>,
    pub state: TenantState,
    pub facts: serde_json::Value,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = tenant)]
struct Row {
    id: uuid::Uuid,
    parent_id: Option<uuid::Uuid>,
    state: String,
    facts: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    metadata: serde_json::Value,
}

impl From<Row> for Tenant {
    fn from(row: Row) -> Self {
        Self {
            id: row.id.into(),
            parent_id: row.parent_id.map(Into::into),
            state: TenantState::parse(&row.state),
            facts: row.facts,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

pub async fn get(conn: &mut AsyncPgConnection, id: TenantId) -> StoreResult<Tenant> {
    tenant::table
        .find(id.as_uuid())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Tenant::from)
        .ok_or(StoreError::NotFound)
}

/// The tenants among `ids` that exist.
pub async fn existing(
    conn: &mut AsyncPgConnection,
    ids: &[uuid::Uuid],
) -> StoreResult<std::collections::BTreeSet<uuid::Uuid>> {
    Ok(tenant::table
        .filter(tenant::id.eq_any(ids))
        .select(tenant::id)
        .load(conn)
        .await?
        .into_iter()
        .collect())
}

/// Creates a tenant with empty metadata; see [`create_with_metadata`].
pub async fn create(
    conn: &mut AsyncPgConnection,
    id: TenantId,
    parent: TenantId,
    facts: &serde_json::Value,
) -> StoreResult<(Tenant, bool)> {
    create_with_metadata(conn, id, parent, facts, &crate::metadata::empty()).await
}

/// Creates a tenant under `parent` with a caller-supplied id. Repeating the
/// call with the same parent and metadata returns the existing tenant; a
/// different parent or metadata is a conflict. Returns the tenant and
/// whether it was created.
// r[impl tenant.tree.single-parent]
// r[impl tenant.authority]
// r[impl metadata.write.create]
pub async fn create_with_metadata(
    conn: &mut AsyncPgConnection,
    id: TenantId,
    parent: TenantId,
    facts: &serde_json::Value,
    metadata: &serde_json::Value,
) -> StoreResult<(Tenant, bool)> {
    if id == ROOT {
        return Err(StoreError::Conflict(
            "the root tenant already exists".into(),
        ));
    }
    let parent_tenant = get(conn, parent).await.map_err(|error| match error {
        StoreError::NotFound => {
            StoreError::Conflict(format!("parent tenant {parent} does not exist"))
        }
        other => other,
    })?;
    if parent_tenant.state == TenantState::Deleted {
        return Err(StoreError::Conflict("the parent tenant is deleted".into()));
    }
    let inserted = diesel::insert_into(tenant::table)
        .values((
            tenant::id.eq(id.as_uuid()),
            tenant::parent_id.eq(parent.as_uuid()),
            tenant::facts.eq(facts),
            tenant::metadata.eq(metadata),
        ))
        .on_conflict_do_nothing()
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .optional()?;
    if let Some(row) = inserted {
        return Ok((row.into(), true));
    }
    let existing = get(conn, id).await?;
    if existing.parent_id != Some(parent) {
        Err(StoreError::Conflict(format!(
            "tenant {id} already exists under another parent"
        )))
    } else if existing.metadata != *metadata {
        Err(StoreError::Conflict(format!(
            "tenant {id} already exists with other metadata"
        )))
    } else {
        Ok((existing, false))
    }
}

pub async fn set_state(
    conn: &mut AsyncPgConnection,
    id: TenantId,
    state: TenantState,
) -> StoreResult<Tenant> {
    if id == ROOT && state != TenantState::Active {
        return Err(StoreError::Conflict(
            "the root tenant cannot be suspended or deleted".into(),
        ));
    }
    diesel::update(tenant::table.find(id.as_uuid()))
        .set((
            tenant::state.eq(state.as_str()),
            tenant::updated_at.eq(diesel::dsl::now),
        ))
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .optional()?
        .map(Tenant::from)
        .ok_or(StoreError::NotFound)
}

pub async fn set_facts(
    conn: &mut AsyncPgConnection,
    id: TenantId,
    facts: &serde_json::Value,
) -> StoreResult<Tenant> {
    diesel::update(tenant::table.find(id.as_uuid()))
        .set((
            tenant::facts.eq(facts),
            tenant::updated_at.eq(diesel::dsl::now),
        ))
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .optional()?
        .map(Tenant::from)
        .ok_or(StoreError::NotFound)
}

/// Tenants, newest first, optionally only children of `parent` or those
/// whose metadata contains `metadata`.
// r[impl metadata.filter]
pub async fn list(
    conn: &mut AsyncPgConnection,
    parent: Option<TenantId>,
    metadata: Option<&serde_json::Value>,
    before: Option<TenantId>,
    limit: i64,
) -> StoreResult<Vec<Tenant>> {
    let mut query = tenant::table.into_boxed();
    if let Some(metadata) = metadata {
        query = query.filter(tenant::metadata.contains(metadata.clone()));
    }
    if let Some(parent) = parent {
        query = query.filter(tenant::parent_id.eq(uuid::Uuid::from(parent)));
    }
    if let Some(before) = before {
        query = query.filter(tenant::id.lt(uuid::Uuid::from(before)));
    }
    Ok(query
        .order(tenant::id.desc())
        .limit(limit)
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(Tenant::from)
        .collect())
}
