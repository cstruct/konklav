use chrono::{DateTime, Utc};
use konklav_core::{MembershipId, SubjectId, TenantId};
use serde::{Deserialize, Serialize};

use crate::RoleAssignment;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    Active,
    Suspended,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Tenant {
    pub id: TenantId,
    pub parent_id: Option<TenantId>,
    pub state: TenantState,
    #[schema(value_type = Object)]
    pub facts: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateTenant {
    /// The parent tenant (a UUID or `root`); `root` when absent.
    pub parent: Option<String>,
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    pub facts: serde_json::Value,
    /// Templates to instantiate roles from, atomically with the tenant.
    #[serde(default)]
    pub templates: Vec<String>,
}

fn empty_object() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SetTenantState {
    pub state: TenantState,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TenantQuery {
    pub parent: Option<String>,
    pub before: Option<TenantId>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TenantPage {
    pub tenants: Vec<Tenant>,
    pub next: Option<TenantId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Active,
    Ended,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Membership {
    pub id: MembershipId,
    pub subject_id: SubjectId,
    pub tenant_id: TenantId,
    pub state: MembershipState,
    #[schema(value_type = Object)]
    pub facts: serde_json::Value,
    /// The identity provider whose claim mapping created it, if any.
    pub managed_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateMembership {
    pub subject: SubjectId,
    /// The tenant (a UUID or `root`).
    pub tenant: String,
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    pub facts: serde_json::Value,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams,
)]
#[into_params(parameter_in = Query)]
pub struct MembershipQuery {
    #[serde(default)]
    pub active: bool,
}

/// A membership with its role assignments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MembershipDetail {
    #[serde(flatten)]
    pub membership: Membership,
    pub assignments: Vec<RoleAssignment>,
}
