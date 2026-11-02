use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use konklav_authz::Scope;
use konklav_core::{ShareId, TenantId};
use serde::{Deserialize, Serialize};

/// Where a share is in its life: `offered` by the owner, `accepted` for the
/// recipient, or `revoked` by either side, which is final.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShareState {
    Offered,
    Accepted,
    Revoked,
}

/// Which side of a share: the tenant that owns the scope, or the one it is
/// shared with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShareSide {
    Owner,
    Recipient,
}

/// What a share offers. Changing any of it offers the share again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ShareTerms {
    pub owner: TenantId,
    /// The owner's scope.
    pub scope: Scope,
    pub recipient: TenantId,
    /// The recipient's scope the share is for; tenant-wide when absent.
    #[serde(default)]
    pub recipient_scope: Option<Scope>,
    /// Actions or action groups. Control-plane capabilities can't be
    /// shared.
    pub actions: BTreeSet<String>,
    /// Share attributes: facts declared in the catalog with target `share`.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub attributes: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub valid_from: Option<DateTime<Utc>>,
    /// After `valid_from`, when both are set.
    #[serde(default)]
    pub valid_until: Option<DateTime<Utc>>,
}

/// A share of one tenant's scope with another tenant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Share {
    pub id: ShareId,
    #[serde(flatten)]
    pub terms: ShareTerms,
    pub state: ShareState,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<ShareSide>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RevokeShare {
    /// Which side revokes.
    pub by: ShareSide,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams,
)]
#[into_params(parameter_in = Query)]
pub struct ShareQuery {
    /// Only shares where the tenant is on this side; both when absent.
    pub side: Option<ShareSide>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ShareList {
    pub shares: Vec<Share>,
}
