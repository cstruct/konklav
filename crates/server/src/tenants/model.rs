use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::types::{CatalogRevision, PolicyRevision, RoleKey, SubjectId, TenantId};

#[derive(Clone, Debug, Serialize)]
pub struct CompiledTenantModel {
    pub root_tenant: TenantId,
    pub policy_revision: PolicyRevision,
    pub tenants: Vec<CompiledTenant>,
    pub subjects: Vec<CompiledSubject>,
    pub memberships: Vec<CompiledMembership>,
    pub assumption_grants: Vec<CompiledAssumptionGrant>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledTenant {
    pub id: TenantId,
    pub display_name: Option<String>,
    pub parent: Option<TenantId>,
    pub state: String,
    pub lineage: Vec<TenantId>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledSubject {
    pub id: SubjectId,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledMembership {
    pub subject: SubjectId,
    pub tenant: TenantId,
    pub role_keys: Vec<RoleKey>,
    pub tenant_bits_hex: String,
    pub scoped_entries: Vec<CompiledScopeGrant>,
    pub facts: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledScopeGrant {
    pub kind: crate::types::ScopeKind,
    pub id: Option<crate::types::ScopeId>,
    pub bits_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledAssumptionGrant {
    pub subject: SubjectId,
    pub source_tenant: TenantId,
    pub target_tenant: TenantId,
    pub target_role_keys: Vec<RoleKey>,
    pub ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DirectAccessTokenRequest {
    pub subject: SubjectId,
    pub tenant: TenantId,
    pub audience: Option<String>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AssumeAccessTokenRequest {
    pub subject: SubjectId,
    pub source_tenant: TenantId,
    pub target_tenant: TenantId,
    pub audience: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ValidateAccessTokenRequest {
    pub token: String,
    pub expected_tenant: TenantId,
    pub audience: Option<String>,
    pub action: Option<crate::types::ActionName>,
    pub scope_kind: Option<crate::types::ScopeKind>,
    pub scope_id: Option<crate::types::ScopeId>,
    pub require_current_revisions: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    pub token: String,
    pub claims: AccessTokenClaims,
    pub mode: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidateAccessTokenResponse {
    pub valid: bool,
    pub claims: Option<AccessTokenClaims>,
    pub decision: Option<AccessDecision>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessDecision {
    pub action: crate::types::ActionName,
    pub allowed: bool,
    pub matched_scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: SubjectId,
    pub aud: String,
    pub jti: String,
    pub iat: u64,
    pub exp: u64,
    pub tid: TenantId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorChainClaim>,
    pub az: AuthorizationSnapshotClaim,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorChainClaim {
    pub sub: SubjectId,
    pub tid: TenantId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationSnapshotClaim {
    pub catalog_rev: CatalogRevision,
    pub policy_rev: PolicyRevision,
    pub tenant_bits: String,
    pub scopes: Vec<ScopedBitsClaim>,
    pub facts: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopedBitsClaim {
    pub kind: crate::types::ScopeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<crate::types::ScopeId>,
    pub bits: String,
}

impl CompiledTenantModel {
    pub fn find_membership(&self, subject: &str, tenant: &str) -> Option<&CompiledMembership> {
        self.memberships
            .iter()
            .find(|entry| entry.subject == subject && entry.tenant == tenant)
    }

    pub fn find_assumption_grant(
        &self,
        subject: &str,
        source_tenant: &str,
        target_tenant: &str,
    ) -> Option<&CompiledAssumptionGrant> {
        self.assumption_grants.iter().find(|entry| {
            entry.subject == subject
                && entry.source_tenant == source_tenant
                && entry.target_tenant == target_tenant
        })
    }

    pub fn require_active_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<&CompiledTenant, crate::types::DynError> {
        let tenant = self
            .tenants
            .iter()
            .find(|tenant| tenant.id == tenant_id)
            .ok_or_else(|| {
                Box::new(crate::tenants::compile::TenantError::new(format!(
                    "unknown tenant {tenant_id}"
                ))) as crate::types::DynError
            })?;

        if tenant.state != "active" {
            return Err(Box::new(crate::tenants::compile::TenantError::new(
                format!("tenant {tenant_id} is not active"),
            )));
        }

        Ok(tenant)
    }
}
