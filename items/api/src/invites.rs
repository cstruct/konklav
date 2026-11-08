use chrono::{DateTime, Utc};
use konklav_core::MembershipId;
use serde::{Deserialize, Serialize};

use crate::tenancy::empty_object;

/// Invites an email address, optionally into a tenant with roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateInvite {
    /// The invite's id, chosen by the caller so that repeating the request
    /// is safe; generated when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
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
    /// An object, opaque to Konklav, delivered with the invite and handed
    /// over on redemption.
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
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
}

/// Where an invite stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InviteState {
    /// Can still be redeemed.
    Pending,
    Redeemed,
    Revoked,
    /// Expired, or used up its redemption attempts, without being redeemed.
    Expired,
}

/// An invite, without its token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Invite {
    pub id: uuid::Uuid,
    /// The invited address, normalized.
    pub email: String,
    #[schema(required)]
    pub tenant: Option<String>,
    pub roles: Vec<String>,
    #[schema(required)]
    pub membership: Option<MembershipId>,
    pub state: InviteState,
    pub expires_at: DateTime<Utc>,
    /// When it was redeemed or revoked.
    #[schema(required)]
    pub consumed_at: Option<DateTime<Utc>>,
    /// An object, opaque to Konklav.
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    /// Changes whenever `metadata` does; send it as `If-Match` to patch
    /// the metadata only if no one else has since.
    pub metadata_etag: String,
}

/// Which invites to list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct InviteQuery {
    /// Only invites to this tenant (a UUID or `root`).
    pub tenant: Option<String>,
    /// A JSON object of strings, numbers and booleans: only objects whose
    /// metadata has each of its keys at the top level with an equal value.
    pub metadata: Option<String>,
    pub before: Option<uuid::Uuid>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InvitePage {
    pub invites: Vec<Invite>,
    #[schema(required)]
    pub next: Option<uuid::Uuid>,
}
