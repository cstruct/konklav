use conclave_core::{ActionName, RoleKey, TemplateKey, TenantId};
use facet::Facet;
use serde::Serialize;

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct ActionCatalogConfig {
    pub actions: Vec<ActionSpec>,
}

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct ActionSpec {
    pub name: ActionName,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct TemplateConfig {
    pub tenant: TenantId,
    pub key: TemplateKey,
    pub source: Option<TemplateSourceConfig>,
    #[facet(default)]
    pub policies: Vec<PolicySpec>,
}

#[derive(Clone, Debug, Facet, PartialEq, Serialize)]
pub struct RoleConfig {
    pub tenant: TenantId,
    pub key: RoleKey,
    pub template: Option<TemplateKey>,
    #[facet(default)]
    pub policies: Vec<PolicySpec>,
}

#[derive(Clone, Debug, Facet, PartialEq, Eq, Serialize)]
pub struct TemplateSourceConfig {
    pub tenant: TenantId,
    pub key: TemplateKey,
    #[facet(default = default_sync_mode())]
    pub mode: String,
}

#[derive(Clone, Debug, Facet, PartialEq, Eq, Serialize)]
pub struct PolicySpec {
    pub effect: String,
    pub action: ActionName,
    pub scope_kind: Option<conclave_core::ScopeKind>,
    pub scope_id: Option<conclave_core::ScopeId>,
}

fn default_sync_mode() -> String {
    "tracking".to_owned()
}
