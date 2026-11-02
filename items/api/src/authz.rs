use chrono::{DateTime, Utc};
use konklav_core::{MembershipId, SubjectId};
use serde::{Deserialize, Serialize};

/// A resource inside a tenant. Konklav treats the id as opaque.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Scope {
    pub kind: String,
    pub id: String,
}

/// Who a role is assigned to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case", tag = "type", content = "id")]
pub enum AssignmentTarget {
    /// A tenant role, for a membership in the role's tenant.
    Membership(MembershipId),
    /// A global role, for a subject directly.
    Subject(SubjectId),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RoleAssignment {
    pub id: uuid::Uuid,
    pub role_id: uuid::Uuid,
    pub target: AssignmentTarget,
    pub scope: Option<Scope>,
    /// The identity provider whose claim mapping created it, if any.
    pub managed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}
