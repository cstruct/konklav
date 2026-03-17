use conclave_core::{RoleKey, SubjectId, TenantId};
use facet::Facet;
use serde::Serialize;

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct TenantConfig {
    pub id: TenantId,
    pub display_name: Option<String>,
    pub parent: Option<TenantId>,
    #[facet(default = default_tenant_state())]
    pub state: String,
}

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct SubjectConfig {
    pub id: SubjectId,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct MembershipConfig {
    pub subject: SubjectId,
    pub tenant: TenantId,
    #[facet(default)]
    pub roles: Vec<RoleKey>,
    #[facet(default)]
    pub facts: Vec<PortableFactConfig>,
}

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct PortableFactConfig {
    pub key: String,
    pub string: Option<String>,
    pub integer: Option<i64>,
    pub boolean: Option<bool>,
}

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct AssumptionGrantConfig {
    pub subject: SubjectId,
    pub source_tenant: TenantId,
    pub target_tenant: TenantId,
    #[facet(default)]
    pub target_roles: Vec<RoleKey>,
    pub ttl_seconds: Option<u64>,
}

fn default_tenant_state() -> String {
    "active".to_owned()
}
