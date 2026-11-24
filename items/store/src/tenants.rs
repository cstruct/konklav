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

/// The longest a tenant key may be.
pub const KEY_MAX_LEN: usize = 63;

/// Whether `key` is a valid tenant key: lowercase words joined by hyphens,
/// such as `acme-north`, at most [`KEY_MAX_LEN`] long, and not `root`.
// r[impl tenant.key]
#[must_use]
pub fn valid_key(key: &str) -> bool {
    key.len() <= KEY_MAX_LEN
        && key != "root"
        && key
            .split('-')
            .all(|word| !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase()))
}

/// How a tenant is named: by its id (a UUID, or `root`), or by its key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reference {
    Id(TenantId),
    Key(String),
}

/// Parses a tenant reference: a UUID, `root`, or a tenant key. `None` when
/// it is none of them.
#[must_use]
pub fn parse_reference(value: &str) -> Option<Reference> {
    if value == "root" {
        Some(Reference::Id(ROOT))
    } else if let Ok(id) = value.parse() {
        Some(Reference::Id(id))
    } else {
        valid_key(value).then(|| Reference::Key(value.to_owned()))
    }
}

/// The tenant `reference` names: its id, or the id of the tenant with its
/// key. `None` when no tenant has the key; an id is returned as given,
/// whether or not a tenant has it.
// r[impl tenant.key.reference]
pub async fn resolve(
    conn: &mut AsyncPgConnection,
    reference: &Reference,
) -> StoreResult<Option<TenantId>> {
    match reference {
        Reference::Id(id) => Ok(Some(*id)),
        Reference::Key(key) => Ok(tenant::table
            .filter(tenant::key.eq(key))
            .select(tenant::id)
            .first::<uuid::Uuid>(conn)
            .await
            .optional()?
            .map(Into::into)),
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
    /// Its tenant key, if it has one.
    pub key: Option<String>,
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
    key: Option<String>,
}

impl From<Row> for Tenant {
    fn from(row: Row) -> Self {
        Self {
            id: row.id.into(),
            parent_id: row.parent_id.map(Into::into),
            state: TenantState::parse(&row.state),
            facts: row.facts,
            metadata: row.metadata,
            key: row.key,
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
    create_with_metadata(conn, id, parent, facts, &crate::metadata::empty(), None).await
}

/// Creates a tenant under `parent` with a caller-supplied id, and `key` if
/// given. Repeating the call with the same parent, metadata and key returns
/// the existing tenant; a different parent, metadata or key is a conflict,
/// and so is a key another tenant has. Returns the tenant and whether it was
/// created.
// r[impl tenant.tree.single-parent]
// r[impl tenant.authority]
// r[impl metadata.write.create]
pub async fn create_with_metadata(
    conn: &mut AsyncPgConnection,
    id: TenantId,
    parent: TenantId,
    facts: &serde_json::Value,
    metadata: &serde_json::Value,
    key: Option<&str>,
) -> StoreResult<(Tenant, bool)> {
    if key.is_some_and(|key| !valid_key(key)) {
        return Err(StoreError::Conflict(format!(
            "`{}` isn't a tenant key: lowercase words joined by hyphens, at most {KEY_MAX_LEN} characters, not `root`",
            key.unwrap_or_default()
        )));
    }
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
            tenant::key.eq(key),
        ))
        .on_conflict(tenant::id)
        .do_nothing()
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .optional()
        .map_err(|error| StoreError::from_unique_violation(error, "a tenant with this key"))?;
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
    } else if existing.key.as_deref() != key {
        Err(StoreError::Conflict(format!(
            "tenant {id} already exists with another key"
        )))
    } else {
        Ok((existing, false))
    }
}

/// Gives a tenant that has no key `key`. Setting the key it has changes
/// nothing; any other key, or a key another tenant has, is a conflict.
/// Returns the tenant and whether the key was set now.
// r[impl tenant.key]
pub async fn set_key(
    conn: &mut AsyncPgConnection,
    id: TenantId,
    key: &str,
) -> StoreResult<(Tenant, bool)> {
    if !valid_key(key) {
        return Err(StoreError::Conflict(format!(
            "`{key}` isn't a tenant key: lowercase words joined by hyphens, at most {KEY_MAX_LEN} characters, not `root`"
        )));
    }
    let existing = get(conn, id).await?;
    match existing.key.as_deref() {
        Some(had) if had == key => return Ok((existing, false)),
        Some(had) => {
            return Err(StoreError::Conflict(format!(
                "tenant {id} already has the key `{had}`, and a tenant's key never changes"
            )));
        }
        None => {}
    }
    let updated = diesel::update(tenant::table.find(id.as_uuid()))
        .filter(tenant::key.is_null())
        .set((tenant::key.eq(key), tenant::updated_at.eq(diesel::dsl::now)))
        .returning(Row::as_returning())
        .get_result::<Row>(conn)
        .await
        .optional()
        .map_err(|error| StoreError::from_unique_violation(error, "a tenant with this key"))?;
    match updated {
        Some(row) => Ok((row.into(), true)),
        // Keyed meanwhile.
        None => Box::pin(set_key(conn, id, key)).await,
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

#[cfg(test)]
mod tests {
    use super::*;

    // r[verify tenant.key]
    #[test]
    fn keys_are_lowercase_words_joined_by_hyphens() {
        for key in ["acme", "acme-north", "a-b-c"] {
            assert!(valid_key(key), "{key}");
        }
        for key in [
            "",
            "root",
            "Acme",
            "acme1",
            "-acme",
            "acme-",
            "acme--north",
            "acme_north",
            "åsa",
        ] {
            assert!(!valid_key(key), "{key}");
        }
        assert!(valid_key(&"a".repeat(KEY_MAX_LEN)));
        assert!(!valid_key(&"a".repeat(KEY_MAX_LEN + 1)));
    }

    #[test]
    fn references_are_ids_root_or_keys() {
        assert_eq!(parse_reference("root"), Some(Reference::Id(ROOT)));
        let id = TenantId::new_v7();
        assert_eq!(parse_reference(&id.to_string()), Some(Reference::Id(id)));
        assert_eq!(
            parse_reference("acme-north"),
            Some(Reference::Key("acme-north".into()))
        );
        assert_eq!(parse_reference("Not a key"), None);
    }
}
