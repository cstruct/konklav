use serde::Serialize;

use conclave_managed_config::TemplateSourceConfig;

use crate::types::{
    ActionName, CatalogRevision, RoleKey, ScopeId, ScopeKind, TemplateKey, TenantId,
};

#[derive(Clone, Debug, Serialize)]
pub struct CompiledAuthzModel {
    pub catalog_revision: CatalogRevision,
    pub action_count: usize,
    pub actions: Vec<CompiledAction>,
    pub templates: Vec<CompiledTemplate>,
    pub roles: Vec<CompiledRole>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CompiledAction {
    pub name: ActionName,
    pub namespace: String,
    pub bit: usize,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledTemplate {
    pub tenant: TenantId,
    pub key: TemplateKey,
    pub revision: u64,
    pub sync_mode: String,
    pub source: Option<TemplateSourceConfig>,
    pub lineage: Vec<String>,
    pub tenant_allow_bits_hex: String,
    pub tenant_deny_bits_hex: String,
    pub scoped_entries: Vec<CompiledScopeEntry>,
    pub policies: Vec<CompiledPolicy>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledRole {
    pub tenant: TenantId,
    pub key: RoleKey,
    pub revision: u64,
    pub template: Option<TemplateKey>,
    pub tenant_allow_bits_hex: String,
    pub tenant_deny_bits_hex: String,
    pub scoped_entries: Vec<CompiledScopeEntry>,
    pub policies: Vec<CompiledPolicy>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledScopeEntry {
    pub scope_kind: ScopeKind,
    pub scope_id: Option<ScopeId>,
    pub allow_bits_hex: String,
    pub deny_bits_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledPolicy {
    pub effect: String,
    pub selector: ActionName,
    pub expanded_actions: Vec<ActionName>,
    pub bits_hex: String,
    pub scope_kind: Option<ScopeKind>,
    pub scope_id: Option<ScopeId>,
}

impl CompiledAuthzModel {
    pub fn find_role(&self, tenant: &str, key: &str) -> Option<&CompiledRole> {
        self.roles
            .iter()
            .find(|role| role.tenant == tenant && role.key == key)
    }

    pub fn action_bit(&self, action: &str) -> Option<usize> {
        self.actions
            .iter()
            .find(|entry| entry.name == action)
            .map(|entry| entry.bit)
    }
}
