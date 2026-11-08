use chrono::{DateTime, Utc};
use konklav_authz::Policy;
use serde::{Deserialize, Serialize};

use crate::tenancy::empty_object;

/// A reusable role blueprint, which can't be assigned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Template {
    pub id: uuid::Uuid,
    pub key: String,
    pub description: String,
    /// An object, opaque to Konklav.
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    /// Changes whenever `metadata` does; send it as `If-Match` to patch
    /// the metadata only if no one else has since.
    pub metadata_etag: String,
    pub policies: Vec<Policy>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// What a template should look like.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PutTemplate {
    #[serde(default)]
    pub description: String,
    /// An object, opaque to Konklav.
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub policies: Vec<Policy>,
}
