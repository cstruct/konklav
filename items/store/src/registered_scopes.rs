//! Registered scopes: scopes of a registered kind whose owner tenant and
//! containing scopes Konklav records, so requirements can name the scope
//! alone. A scope's tenant never changes; removed scopes are kept so it
//! can't change by removing and recording one again.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::upsert::excluded;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_authz::{Registration, Scope};
use konklav_core::TenantId;
use serde::{Deserialize, Serialize};

use crate::schema::{catalog_scope_kind, registered_scope, tenant};
use crate::{StoreError, StoreResult};

/// The most changes one [`apply`] takes.
pub const MAX_BATCH: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisteredState {
    Active,
    Removed,
}

impl RegisteredState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Removed => "removed",
        }
    }

    fn parse(value: &str) -> Self {
        if value == "removed" {
            Self::Removed
        } else {
            Self::Active
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisteredScope {
    pub kind: String,
    pub id: String,
    pub tenant: TenantId,
    pub containers: Vec<Scope>,
    pub state: RegisteredState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RegisteredScope {
    #[must_use]
    pub fn scope(&self) -> Scope {
        Scope {
            kind: self.kind.clone(),
            id: self.id.clone(),
        }
    }

    /// The record as evaluation takes it: `None` once removed.
    #[must_use]
    pub fn registration(&self) -> Option<Registration> {
        (self.state == RegisteredState::Active).then(|| Registration {
            kind: self.kind.clone(),
            id: self.id.clone(),
            tenant: self.tenant,
            containers: self.containers.clone(),
        })
    }
}

/// One change to a registered scope.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Change {
    /// Records the scope in `tenant`, or replaces its containers.
    Record {
        kind: String,
        id: String,
        tenant: TenantId,
        #[serde(default)]
        containers: Vec<Scope>,
    },
    /// Removes the scope. Removing an unknown or removed scope changes
    /// nothing.
    Remove { kind: String, id: String },
}

impl Change {
    fn scope(&self) -> Scope {
        match self {
            Self::Record { kind, id, .. } | Self::Remove { kind, id } => Scope {
                kind: kind.clone(),
                id: id.clone(),
            },
        }
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = registered_scope)]
struct Row {
    kind: String,
    id: String,
    tenant_id: uuid::Uuid,
    containers: serde_json::Value,
    state: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Row {
    fn into_scope(self) -> StoreResult<RegisteredScope> {
        Ok(RegisteredScope {
            kind: self.kind,
            id: self.id,
            tenant: self.tenant_id.into(),
            containers: serde_json::from_value(self.containers)
                .map_err(|e| diesel::result::Error::DeserializationError(Box::new(e)))?,
            state: RegisteredState::parse(&self.state),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

pub async fn get(conn: &mut AsyncPgConnection, scope: &Scope) -> StoreResult<RegisteredScope> {
    registered_scope::table
        .find((&scope.kind, &scope.id))
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .ok_or(StoreError::NotFound)?
        .into_scope()
}

/// Up to `limit` records, active and removed, after `after` in kind and
/// id order.
pub async fn list(
    conn: &mut AsyncPgConnection,
    after: Option<&Scope>,
    limit: i64,
) -> StoreResult<Vec<RegisteredScope>> {
    let mut query = registered_scope::table
        .select(Row::as_select())
        .order((registered_scope::kind, registered_scope::id))
        .limit(limit)
        .into_boxed();
    if let Some(after) = after {
        query = query.filter(
            registered_scope::kind
                .gt(after.kind.clone())
                .or(registered_scope::kind
                    .eq(after.kind.clone())
                    .and(registered_scope::id.gt(after.id.clone()))),
        );
    }
    query
        .load(conn)
        .await?
        .into_iter()
        .map(Row::into_scope)
        .collect()
}

/// The records of `scopes` that exist, active or removed.
pub async fn get_many(
    conn: &mut AsyncPgConnection,
    scopes: &[Scope],
) -> StoreResult<BTreeMap<Scope, RegisteredScope>> {
    let mut found = BTreeMap::new();
    // Grouped by kind, so each kind is one indexed lookup.
    let mut by_kind: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for scope in scopes {
        by_kind.entry(&scope.kind).or_default().push(&scope.id);
    }
    for (kind, ids) in by_kind {
        let rows: Vec<Row> = registered_scope::table
            .filter(registered_scope::kind.eq(kind))
            .filter(registered_scope::id.eq_any(ids))
            .select(Row::as_select())
            .load(conn)
            .await?;
        for row in rows {
            let record = row.into_scope()?;
            found.insert(record.scope(), record);
        }
    }
    Ok(found)
}

/// What evaluation needs for the registered scopes among `scopes`: a
/// record for each, `None` when unknown or removed.
pub async fn registrations(
    conn: &mut AsyncPgConnection,
    kinds: &BTreeSet<String>,
    scopes: &[Scope],
) -> StoreResult<BTreeMap<Scope, Option<Registration>>> {
    let wanted: Vec<Scope> = scopes
        .iter()
        .filter(|scope| kinds.contains(&scope.kind))
        .cloned()
        .collect();
    let found = get_many(conn, &wanted).await?;
    Ok(wanted
        .into_iter()
        .map(|scope| {
            let record = found.get(&scope).and_then(RegisteredScope::registration);
            (scope, record)
        })
        .collect())
}

/// A scope's record as [`apply`] writes it.
type Write = (Scope, TenantId, Vec<Scope>, RegisteredState);

/// The writes `changes` make, given the current records, the catalog's
/// kinds (name to whether registered) and the tenants that exist; every
/// change that can't be applied fails it.
fn plan(
    changes: &[Change],
    existing: &BTreeMap<Scope, RegisteredScope>,
    kinds: &BTreeMap<String, bool>,
    known_tenants: &BTreeSet<uuid::Uuid>,
) -> StoreResult<Vec<Write>> {
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    let mut writes = Vec::new();
    for (index, change) in changes.iter().enumerate() {
        let scope = change.scope();
        let mut problem = |message: String| {
            problems.push(format!(
                "change {index} ({}/{}): {message}",
                scope.kind, scope.id
            ));
        };
        if !seen.insert(scope.clone()) {
            problem("the scope appears more than once".into());
            continue;
        }
        if kinds.get(&scope.kind) != Some(&true) {
            problem("the kind isn't a registered scope kind".into());
            continue;
        }
        let current = existing.get(&scope);
        match change {
            Change::Record {
                tenant, containers, ..
            } => {
                if !known_tenants.contains(tenant.as_uuid()) {
                    problem("the tenant doesn't exist".into());
                    continue;
                }
                if let Some(current) = current
                    && current.tenant != *tenant
                {
                    problem(format!(
                        "it is registered in tenant {}, and its tenant can't change",
                        current.tenant
                    ));
                    continue;
                }
                if let Some(bad) = containers
                    .iter()
                    .find(|container| kinds.get(&container.kind) != Some(&false))
                {
                    problem(format!(
                        "containing scope kind `{}` isn't a declared kind that isn't registered",
                        bad.kind
                    ));
                    continue;
                }
                let containers: Vec<Scope> = containers
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let unchanged = current.is_some_and(|current| {
                    current.state == RegisteredState::Active && current.containers == containers
                });
                if !unchanged {
                    writes.push((scope, *tenant, containers, RegisteredState::Active));
                }
            }
            Change::Remove { .. } => {
                if let Some(current) = current
                    && current.state == RegisteredState::Active
                {
                    writes.push((
                        scope,
                        current.tenant,
                        current.containers.clone(),
                        RegisteredState::Removed,
                    ));
                }
            }
        }
    }
    if !problems.is_empty() {
        return Err(StoreError::Conflict(problems.join("; ")));
    }
    Ok(writes)
}

/// Applies `changes` all or nothing, and returns each scope's record
/// afterwards, `None` for removing an unknown scope. Every change that
/// can't be applied is named in the error.
///
/// It writes everything in one statement, so the transaction gets one
/// `scope.changed` event; run it in a transaction.
// r[impl authz.registered.shape]
// r[impl authz.registered.tenant-fixed]
// r[impl authz.registered.containers]
// r[impl authz.registered.batch]
pub async fn apply(
    conn: &mut AsyncPgConnection,
    changes: &[Change],
) -> StoreResult<Vec<Option<RegisteredScope>>> {
    if changes.len() > MAX_BATCH {
        return Err(StoreError::Conflict(format!(
            "at most {MAX_BATCH} changes at once"
        )));
    }
    let scopes: Vec<Scope> = changes.iter().map(Change::scope).collect();
    let existing = get_many(conn, &scopes).await?;
    let kinds: BTreeMap<String, bool> = catalog_scope_kind::table
        .select((catalog_scope_kind::name, catalog_scope_kind::registered))
        .load::<(String, bool)>(conn)
        .await?
        .into_iter()
        .collect();
    let tenants: Vec<uuid::Uuid> = changes
        .iter()
        .filter_map(|change| match change {
            Change::Record { tenant, .. } => Some(*tenant.as_uuid()),
            Change::Remove { .. } => None,
        })
        .collect();
    let known_tenants: BTreeSet<uuid::Uuid> = tenant::table
        .filter(tenant::id.eq_any(&tenants))
        .select(tenant::id)
        .load(conn)
        .await?
        .into_iter()
        .collect();

    let writes = plan(changes, &existing, &kinds, &known_tenants)?;

    if !writes.is_empty() {
        let rows = writes
            .iter()
            .map(|(scope, tenant, containers, state)| {
                Ok((
                    registered_scope::kind.eq(&scope.kind),
                    registered_scope::id.eq(&scope.id),
                    registered_scope::tenant_id.eq(tenant.as_uuid()),
                    registered_scope::containers.eq(serde_json::to_value(containers)
                        .map_err(|e| StoreError::Conflict(e.to_string()))?),
                    registered_scope::state.eq(state.as_str()),
                ))
            })
            .collect::<StoreResult<Vec<_>>>()?;
        diesel::insert_into(registered_scope::table)
            .values(rows)
            .on_conflict((registered_scope::kind, registered_scope::id))
            .do_update()
            .set((
                registered_scope::containers.eq(excluded(registered_scope::containers)),
                registered_scope::state.eq(excluded(registered_scope::state)),
                registered_scope::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .await
            .map_err(StoreError::from_constraint)?;
    }

    let after = get_many(conn, &scopes).await?;
    Ok(scopes
        .iter()
        .map(|scope| after.get(scope).cloned())
        .collect())
}

/// The registered scopes `requirements` name, with the catalog's
/// registered `kinds`, as evaluation takes them.
pub async fn for_requirements(
    conn: &mut AsyncPgConnection,
    kinds: BTreeSet<String>,
    requirements: &konklav_authz::Requirements,
) -> StoreResult<konklav_authz::RegisteredScopes> {
    let scopes: Vec<Scope> = requirements
        .scopes
        .iter()
        .map(|required| Scope {
            kind: required.kind.clone(),
            id: required.id.clone(),
        })
        .collect();
    let records = registrations(conn, &kinds, &scopes).await?;
    Ok(konklav_authz::RegisteredScopes { kinds, records })
}
