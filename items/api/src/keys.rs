use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A key Konklav signs tokens with, without its key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SigningKey {
    pub kid: String,
    pub algorithm: String,
    pub published_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RevokedKey {
    pub kid: String,
    /// Whether this call revoked it; `false` when it already was.
    pub revoked: bool,
}
