use chrono::{DateTime, Utc};
use konklav_core::{MembershipId, SubjectId, TenantId};
use serde::{Deserialize, Serialize};

use crate::tenancy::empty_object;

/// Where an access request stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestState {
    /// Waiting for an operator.
    Pending,
    /// Approved: the subject is a member.
    Approved,
    Denied,
    /// Withdrawn by the subject, or because it was erased.
    Withdrawn,
}

/// A signed-in subject's request for a membership in a tenant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AccessRequest {
    pub id: uuid::Uuid,
    pub subject_id: SubjectId,
    pub tenant_id: TenantId,
    pub state: AccessRequestState,
    /// Once approved, the membership the approval created, or found when
    /// the subject had become a member meanwhile.
    #[schema(required)]
    pub membership_id: Option<MembershipId>,
    pub created_at: DateTime<Utc>,
    #[schema(required)]
    pub decided_at: Option<DateTime<Utc>>,
    /// Who approved, denied or withdrew it; null for the bootstrap token or
    /// erasure.
    #[schema(required)]
    pub decided_by: Option<SubjectId>,
}

/// Which access requests to list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AccessRequestQuery {
    /// Only requests for this tenant (a UUID or `root`).
    pub tenant: Option<String>,
    /// Only this subject's requests.
    pub subject: Option<SubjectId>,
    pub state: Option<AccessRequestState>,
    pub before: Option<uuid::Uuid>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AccessRequestPage {
    pub access_requests: Vec<AccessRequest>,
    #[schema(required)]
    pub next: Option<uuid::Uuid>,
}

/// Approves an access request: the subject becomes a member of the tenant.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApproveAccessRequest {
    /// The id of the membership the approval creates, so that a relying
    /// system can name it; generated when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<MembershipId>,
    /// Role keys in the tenant to assign to the membership.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Membership facts.
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    pub facts: serde_json::Value,
    /// The membership's metadata, an object opaque to Konklav.
    #[serde(default = "crate::metadata::empty_object")]
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
}
