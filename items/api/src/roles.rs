use chrono::{DateTime, Utc};
use konklav_authz::Policy;
use konklav_core::TenantId;
use serde::{Deserialize, Serialize};

use crate::tenancy::empty_object;

/// A role: tenant-local, or global when the root tenant owns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Role {
    pub id: uuid::Uuid,
    pub tenant_id: TenantId,
    pub key: String,
    /// The key of the template the role derives from.
    pub template: Option<String>,
    pub priority: i32,
    /// An object, opaque to Konklav.
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    /// The role's own policies, which override its template's.
    pub policies: Vec<Policy>,
    /// Defined by Konklav, under a reserved key; it can't be written.
    pub builtin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// What a role should look like.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PutRole {
    /// The key of a template to derive from.
    pub template: Option<String>,
    /// Between policies for the same action at the same level, the higher
    /// priority wins; at equal priority, a deny wins.
    #[serde(default)]
    pub priority: i32,
    /// An object, opaque to Konklav.
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

/// The result of a delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Deleted {
    /// Whether this call deleted it; `false` when there was nothing to
    /// delete.
    pub deleted: bool,
}
