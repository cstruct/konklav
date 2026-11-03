use chrono::{DateTime, Utc};
use konklav_authz::Scope;
use konklav_core::{MembershipId, SubjectId};
use serde::{Deserialize, Serialize};

/// Who a role is assigned to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case", tag = "type", content = "id")]
pub enum AssignmentTarget {
    /// A tenant role, for a membership in the role's tenant.
    #[schema(title = "AssignmentTargetMembership")]
    Membership(MembershipId),
    /// A global role, for a subject directly.
    #[schema(title = "AssignmentTargetSubject")]
    Subject(SubjectId),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RoleAssignment {
    pub id: uuid::Uuid,
    pub role_id: uuid::Uuid,
    pub target: AssignmentTarget,
    #[schema(required)]
    pub scope: Option<Scope>,
    /// The identity provider whose claim mapping created it, if any.
    #[schema(required)]
    pub managed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A role to assign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssignRole {
    /// The assignment's id, chosen by the caller so that repeating the
    /// request is safe; generated when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
    /// The role's key in the membership's tenant (or in root for global
    /// assignments).
    pub role: String,
    /// Where in the tenant the role applies; tenant-wide when absent.
    /// Global assignments have none.
    pub scope: Option<Scope>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EntitlementQuery {
    /// The tenant (a UUID or `root`); global entitlements only when absent.
    pub tenant: Option<String>,
}
