use chrono::{DateTime, Utc};
use konklav_core::{Cursor, MembershipId};
use serde::{Deserialize, Serialize};

use crate::tenancy::empty_object;

/// Invites an email address, optionally into a tenant with roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateInvite {
    pub email: String,
    /// A tenant (UUID or `root`) to join on redemption.
    pub tenant: Option<String>,
    /// Role keys in that tenant to assign.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Membership facts.
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    pub facts: serde_json::Value,
    /// The id of the membership redemption creates, so a relying system's
    /// own record of the pending member keeps its id.
    pub membership: Option<MembershipId>,
    /// Clamped to between 1 hour and 30 days.
    #[serde(default = "default_hours")]
    pub expires_in_hours: i64,
}

fn default_hours() -> i64 {
    72
}

/// A created invite. Its token is never returned: it is only delivered to
/// the invited address, as a `delivery.requested` event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreatedInvite {
    pub invite_id: uuid::Uuid,
    pub expires_at: DateTime<Utc>,
    #[schema(required)]
    pub cursor: Option<Cursor>,
}
