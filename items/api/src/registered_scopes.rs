use chrono::{DateTime, Utc};
use konklav_authz::Scope;
use konklav_core::{Cursor, TenantId};
use serde::{Deserialize, Serialize};

/// Whether a registered scope is recorded, or has been removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegisteredScopeState {
    Active,
    Removed,
}

/// A relying system's object, recorded with its tenant and containing
/// scopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RegisteredScope {
    pub kind: String,
    pub id: String,
    /// The owner tenant. A removed scope keeps it, so it can only be
    /// recorded again in the same one.
    pub tenant: TenantId,
    /// Scopes of kinds that aren't registered which the scope belongs to.
    pub containers: Vec<Scope>,
    pub state: RegisteredScopeState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Records a scope in a tenant, or replaces its containing scopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RecordRegisteredScope {
    pub tenant: TenantId,
    #[serde(default)]
    pub containers: Vec<Scope>,
}

/// One change to a registered scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RegisteredScopeChange {
    /// Records the scope in `tenant`, or replaces its containers.
    #[schema(title = "RegisteredScopeChangeRecord")]
    Record {
        kind: String,
        id: String,
        tenant: TenantId,
        #[serde(default)]
        containers: Vec<Scope>,
    },
    /// Removes the scope. Removing an unknown or removed scope changes
    /// nothing.
    #[schema(title = "RegisteredScopeChangeRemove")]
    Remove { kind: String, id: String },
}

/// Up to 1000 changes, applied in order, all or nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RegisteredScopeChanges {
    pub changes: Vec<RegisteredScopeChange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RegisteredScopeBatch {
    /// Each change's scope afterwards, in order; `null` for removing an
    /// unknown scope.
    pub scopes: Vec<Option<RegisteredScope>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}
