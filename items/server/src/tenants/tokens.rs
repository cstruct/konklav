use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use conclave_relying_auth::{
    AccessDecision, AccessTokenClaims, ActionCatalogEntry, ActorChainClaim,
    AuthorizationSnapshotClaim, JwtSigner, JwtVerifier, ScopedBitsClaim, ValidationOptions,
};
use serde_json::Value;

use crate::authz::CompiledAuthzModel;
use crate::config::JwtConfig;
use crate::types::DynError;

use super::compile::TenantError;
use super::model::{
    AccessTokenResponse, AssumeAccessTokenRequest, CompiledEffectiveGrant, CompiledScopeGrant,
    CompiledTenantModel, DirectAccessTokenRequest, ValidateAccessTokenRequest,
    ValidateAccessTokenResponse,
};

impl CompiledTenantModel {
    pub fn issue_direct_token(
        &self,
        authz: &CompiledAuthzModel,
        jwt: &JwtConfig,
        signer: &JwtSigner,
        request: &DirectAccessTokenRequest,
    ) -> Result<AccessTokenResponse, DynError> {
        let grant = self
            .find_direct_effective_grant(&request.subject, &request.tenant)
            .ok_or_else(|| {
                Box::new(TenantError::new(format!(
                    "subject {} has no effective grant in tenant {}",
                    request.subject, request.tenant
                ))) as DynError
            })?;
        let claims = issue_effective_grant_token(
            authz.catalog_revision,
            self.policy_revision,
            jwt,
            grant,
            request.audience.as_deref(),
            Some(request.ttl_seconds.unwrap_or(jwt.ttl_seconds).max(1)),
            None,
        )?;
        let token = signer.sign(&claims)?;

        Ok(AccessTokenResponse {
            token,
            claims,
            mode: "direct".to_owned(),
        })
    }

    // r[impl authn.session.explicit-assumption]
    // r[impl authn.assumption.conclave-action]
    // r[impl authn.assumption.time-bounded]
    // r[impl authn.assumption.target-context]
    // r[impl authz.control-plane.capability.assumption-separate]
    // r[impl user.assumption.delegated-principal]
    pub fn issue_assumed_token(
        &self,
        authz: &CompiledAuthzModel,
        jwt: &JwtConfig,
        signer: &JwtSigner,
        request: &AssumeAccessTokenRequest,
    ) -> Result<AccessTokenResponse, DynError> {
        let grant = self
            .find_assumed_effective_grant(
                &request.subject,
                &request.source_tenant,
                &request.target_tenant,
            )
            .ok_or_else(|| {
                Box::new(TenantError::new(format!(
                    "subject {} has no assumption grant from {} to {}",
                    request.subject, request.source_tenant, request.target_tenant
                ))) as DynError
            })?;
        let claims = issue_effective_grant_token(
            authz.catalog_revision,
            self.policy_revision,
            jwt,
            grant,
            request.audience.as_deref(),
            None,
            Some(ActorChainClaim {
                sub: request.subject.clone(),
                tid: request.source_tenant.clone(),
            }),
        )?;
        let token = signer.sign(&claims)?;

        Ok(AccessTokenResponse {
            token,
            claims,
            mode: "assumed".to_owned(),
        })
    }

    // r[impl token.access.use.offline-evaluation]
    // r[impl token.access.use.staleness-bounds]
    // r[depends item.relying-auth.validation-options]
    // r[depends item.relying-auth.offline-decision-evaluation]
    pub fn validate_access_token(
        &self,
        authz: &CompiledAuthzModel,
        jwt: &JwtConfig,
        verifier: &JwtVerifier,
        request: &ValidateAccessTokenRequest,
    ) -> Result<ValidateAccessTokenResponse, DynError> {
        let actions: Vec<ActionCatalogEntry> = authz
            .actions
            .iter()
            .map(|entry| ActionCatalogEntry {
                name: entry.name.clone(),
                bit: entry.bit,
            })
            .collect();
        validate_access_token_with_current_metadata(
            jwt,
            verifier,
            request,
            authz.catalog_revision,
            self.policy_revision,
            &actions,
        )
    }
}

pub fn validate_access_token_with_current_metadata(
    jwt: &JwtConfig,
    verifier: &JwtVerifier,
    request: &ValidateAccessTokenRequest,
    current_catalog_revision: u32,
    current_policy_revision: crate::types::PolicyRevision,
    actions: &[ActionCatalogEntry],
) -> Result<ValidateAccessTokenResponse, DynError> {
    let now = now_unix_seconds()?;
    let validated = verifier.verify(
        &request.token,
        actions,
        ValidationOptions {
            issuer: Some(&jwt.issuer),
            audience: request.audience.as_deref(),
            expected_tenant: Some(&request.expected_tenant),
            current_catalog_revision: request
                .require_current_revisions
                .unwrap_or(true)
                .then_some(current_catalog_revision),
            current_policy_revision: request
                .require_current_revisions
                .unwrap_or(true)
                .then_some(current_policy_revision),
            action: request.action.as_deref(),
            scope_kind: request.scope_kind.as_deref(),
            scope_id: request.scope_id.as_deref(),
        },
    )?;
    let claims = validated.claims;

    if claims.exp <= now {
        return Ok(ValidateAccessTokenResponse {
            valid: false,
            claims: Some(claims),
            decision: None,
            error: Some("token has expired".to_owned()),
        });
    }

    Ok(ValidateAccessTokenResponse {
        valid: validated
            .decision
            .as_ref()
            .is_none_or(|decision| decision.allowed),
        claims: Some(claims),
        decision: validated.decision.map(|entry| AccessDecision {
            action: entry.action,
            allowed: entry.allowed,
            matched_scope: entry.matched_scope,
        }),
        error: None,
    })
}

pub fn issue_effective_grant_token(
    catalog_revision: u32,
    policy_revision: crate::types::PolicyRevision,
    jwt: &JwtConfig,
    grant: &CompiledEffectiveGrant,
    audience: Option<&str>,
    ttl_override_seconds: Option<u64>,
    actor_chain: Option<ActorChainClaim>,
) -> Result<AccessTokenClaims, DynError> {
    ensure_effective_grant_tenants_active(grant)?;
    let ttl_seconds = ttl_override_seconds
        .or(grant.ttl_seconds)
        .unwrap_or(jwt.ttl_seconds)
        .max(1);
    build_access_token_claims(
        catalog_revision,
        jwt,
        &grant.subject,
        &grant.target_tenant,
        audience,
        ttl_seconds,
        actor_chain,
        grant.tenant_bits_hex.clone(),
        grant.scoped_entries.clone(),
        grant.facts.clone(),
        policy_revision,
    )
}

fn ensure_effective_grant_tenants_active(grant: &CompiledEffectiveGrant) -> Result<(), DynError> {
    if grant.target_tenant_state != "active" {
        return Err(Box::new(TenantError::new(format!(
            "tenant {} is not active",
            grant.target_tenant
        ))));
    }

    if let (Some(source_tenant), Some(source_state)) =
        (&grant.source_tenant, &grant.source_tenant_state)
    {
        if source_state != "active" {
            return Err(Box::new(TenantError::new(format!(
                "tenant {} is not active",
                source_tenant
            ))));
        }
    }

    Ok(())
}

// r[impl token.access.jwt.standard-claims]
// r[impl token.access.context.target-tenant]
// r[impl token.access.context.actor-chain]
// r[impl token.access.authz.snapshot-claim]
// r[impl token.access.authz.catalog-revision]
// r[impl token.access.authz.policy-revision]
// r[impl token.access.authz.tenant-bits]
// r[impl token.access.authz.scoped-bits]
// r[impl token.access.authz.portable-facts]
// r[impl token.access.authz.no-arbitrary-dsl]
// r[impl authn.session.tenant-awareness]
// r[impl authz.token.self-contained-claims]
fn build_access_token_claims(
    catalog_revision: u32,
    jwt: &JwtConfig,
    subject: &str,
    target_tenant: &str,
    audience: Option<&str>,
    ttl_seconds: u64,
    actor_chain: Option<ActorChainClaim>,
    tenant_bits: String,
    scoped_entries: Vec<CompiledScopeGrant>,
    facts: BTreeMap<String, Value>,
    policy_revision: crate::types::PolicyRevision,
) -> Result<AccessTokenClaims, DynError> {
    let iat = now_unix_seconds()?;
    let exp = iat + ttl_seconds.max(1);

    Ok(AccessTokenClaims {
        iss: jwt.issuer.clone(),
        sub: subject.to_owned(),
        aud: audience.unwrap_or(&jwt.default_audience).to_owned(),
        jti: build_token_id(subject, target_tenant, iat, exp, actor_chain.as_ref()),
        iat,
        exp,
        tid: target_tenant.to_owned(),
        act: actor_chain,
        az: AuthorizationSnapshotClaim {
            catalog_rev: catalog_revision,
            policy_rev: policy_revision,
            tenant_bits,
            scopes: scoped_entries
                .into_iter()
                .map(|entry| ScopedBitsClaim {
                    kind: entry.kind,
                    id: entry.id,
                    bits: entry.bits_hex,
                })
                .collect(),
            facts: facts.into_iter().collect(),
        },
    })
}

fn now_unix_seconds() -> Result<u64, DynError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn build_token_id(
    subject: &str,
    target_tenant: &str,
    issued_at: u64,
    expires_at: u64,
    actor_chain: Option<&ActorChainClaim>,
) -> String {
    let mut pieces = vec![
        subject.to_owned(),
        target_tenant.to_owned(),
        issued_at.to_string(),
        expires_at.to_string(),
    ];

    if let Some(actor_chain) = actor_chain {
        pieces.push(actor_chain.tid.clone());
    }

    format!("jti-{:016x}", fnv1a64(pieces.join(":").as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    bytes.iter().fold(OFFSET, |hash, byte| {
        let hash = hash ^ u64::from(*byte);
        hash.wrapping_mul(PRIME)
    })
}
