use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::authz::CompiledAuthzModel;
use crate::config::JwtConfig;
use crate::types::DynError;

use super::compile::{compile_entitlements, tenant_is_descendant_of, Bitset, TenantError};
use super::model::{
    AccessDecision, AccessTokenClaims, AccessTokenResponse, ActorChainClaim,
    AssumeAccessTokenRequest, AuthorizationSnapshotClaim, CompiledScopeGrant, CompiledTenantModel,
    DirectAccessTokenRequest, ScopedBitsClaim, ValidateAccessTokenRequest,
    ValidateAccessTokenResponse,
};

type HmacSha256 = Hmac<Sha256>;

impl CompiledTenantModel {
    pub fn issue_direct_token(
        &self,
        authz: &CompiledAuthzModel,
        jwt: &JwtConfig,
        request: &DirectAccessTokenRequest,
    ) -> Result<AccessTokenResponse, DynError> {
        let membership = self
            .find_membership(&request.subject, &request.tenant)
            .ok_or_else(|| {
                Box::new(TenantError::new(format!(
                    "subject {} has no membership in tenant {}",
                    request.subject, request.tenant
                ))) as DynError
            })?;

        let tenant = self.require_active_tenant(&request.tenant)?;
        let ttl_seconds = request.ttl_seconds.unwrap_or(jwt.ttl_seconds).max(1);
        let claims = build_access_token_claims(
            authz,
            jwt,
            &request.subject,
            &tenant.id,
            request.audience.as_deref(),
            ttl_seconds,
            None,
            membership.tenant_bits_hex.clone(),
            membership.scoped_entries.clone(),
            membership.facts.clone(),
            self.policy_revision,
        )?;
        let token = encode_access_token(&claims, &jwt.signing_secret)?;

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
        request: &AssumeAccessTokenRequest,
    ) -> Result<AccessTokenResponse, DynError> {
        let source_membership = self
            .find_membership(&request.subject, &request.source_tenant)
            .ok_or_else(|| {
                Box::new(TenantError::new(format!(
                    "subject {} has no membership in source tenant {}",
                    request.subject, request.source_tenant
                ))) as DynError
            })?;
        let source_tenant = self.require_active_tenant(&request.source_tenant)?;
        let target_tenant = self.require_active_tenant(&request.target_tenant)?;
        let grant = self
            .find_assumption_grant(
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

        if !tenant_is_descendant_of(&target_tenant, &source_tenant.id) {
            return Err(Box::new(TenantError::new(format!(
                "tenant {} is not a descendant of {}",
                target_tenant.id, source_tenant.id
            ))));
        }

        let (tenant_bits, scoped_entries) =
            compile_entitlements(&target_tenant.id, &grant.target_role_keys, authz)?;
        let claims = build_access_token_claims(
            authz,
            jwt,
            &request.subject,
            &target_tenant.id,
            request.audience.as_deref(),
            grant.ttl_seconds,
            Some(ActorChainClaim {
                sub: request.subject.clone(),
                tid: source_tenant.id.clone(),
            }),
            tenant_bits,
            scoped_entries,
            source_membership.facts.clone(),
            self.policy_revision,
        )?;
        let token = encode_access_token(&claims, &jwt.signing_secret)?;

        Ok(AccessTokenResponse {
            token,
            claims,
            mode: "assumed".to_owned(),
        })
    }

    // r[impl token.access.use.offline-evaluation]
    // r[impl token.access.use.staleness-bounds]
    pub fn validate_access_token(
        &self,
        authz: &CompiledAuthzModel,
        jwt: &JwtConfig,
        request: &ValidateAccessTokenRequest,
    ) -> Result<ValidateAccessTokenResponse, DynError> {
        let claims = decode_access_token(&request.token, &jwt.signing_secret)?;
        let now = now_unix_seconds()?;

        if claims.exp <= now {
            return Ok(ValidateAccessTokenResponse {
                valid: false,
                claims: Some(claims),
                decision: None,
                error: Some("token has expired".to_owned()),
            });
        }

        if claims.tid != request.expected_tenant {
            let actual_tenant = claims.tid.clone();
            return Ok(ValidateAccessTokenResponse {
                valid: false,
                claims: Some(claims),
                decision: None,
                error: Some(format!(
                    "token targets tenant {}, expected {}",
                    actual_tenant, request.expected_tenant
                )),
            });
        }

        if let Some(audience) = request.audience.as_deref() {
            if claims.aud != audience {
                let actual_audience = claims.aud.clone();
                return Ok(ValidateAccessTokenResponse {
                    valid: false,
                    claims: Some(claims),
                    decision: None,
                    error: Some(format!(
                        "token audience {} does not match {}",
                        actual_audience, audience
                    )),
                });
            }
        }

        if request.require_current_revisions.unwrap_or(true)
            && (claims.az.catalog_rev != authz.catalog_revision
                || claims.az.policy_rev != self.policy_revision)
        {
            return Ok(ValidateAccessTokenResponse {
                valid: false,
                claims: Some(claims),
                decision: None,
                error: Some("token authorization snapshot is stale".to_owned()),
            });
        }

        let decision = if let Some(action) = request.action.as_deref() {
            let action_bit = authz.action_bit(action).ok_or_else(|| {
                Box::new(TenantError::new(format!("unknown action {action}"))) as DynError
            })?;
            let (allowed, matched_scope) = evaluate_action(
                &claims.az,
                action_bit,
                request.scope_kind.as_deref(),
                request.scope_id.as_deref(),
            )?;

            Some(AccessDecision {
                action: action.to_owned(),
                allowed,
                matched_scope,
            })
        } else {
            None
        };

        Ok(ValidateAccessTokenResponse {
            valid: decision.as_ref().is_none_or(|entry| entry.allowed),
            claims: Some(claims),
            decision,
            error: None,
        })
    }
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
    authz: &CompiledAuthzModel,
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
    let jti = build_token_id(subject, target_tenant, iat, exp, actor_chain.as_ref());

    Ok(AccessTokenClaims {
        iss: jwt.issuer.clone(),
        sub: subject.to_owned(),
        aud: audience.unwrap_or(&jwt.default_audience).to_owned(),
        jti,
        iat,
        exp,
        tid: target_tenant.to_owned(),
        act: actor_chain,
        az: AuthorizationSnapshotClaim {
            catalog_rev: authz.catalog_revision,
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

fn encode_access_token(
    claims: &AccessTokenClaims,
    signing_secret: &str,
) -> Result<String, DynError> {
    if signing_secret.is_empty() {
        return Err(Box::new(TenantError::new(
            "jwt signing secret cannot be empty",
        )));
    }

    let header = serde_json::json!({
        "alg": "HS256",
        "typ": "JWT",
    });
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signature = sign_hs256(signing_secret, &header, &claims)?;

    Ok(format!("{header}.{claims}.{signature}"))
}

fn decode_access_token(token: &str, signing_secret: &str) -> Result<AccessTokenClaims, DynError> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return Err(Box::new(TenantError::new(
            "token does not contain three JWT segments",
        )));
    }

    let expected_signature = sign_hs256(signing_secret, segments[0], segments[1])?;
    if expected_signature != segments[2] {
        return Err(Box::new(TenantError::new(
            "token signature verification failed",
        )));
    }

    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0])?)?;
    if header.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Err(Box::new(TenantError::new("unsupported JWT alg")));
    }

    Ok(serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(segments[1])?,
    )?)
}

fn sign_hs256(signing_secret: &str, header: &str, claims: &str) -> Result<String, DynError> {
    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes())
        .map_err(|_| Box::new(TenantError::new("invalid jwt signing secret")) as DynError)?;
    mac.update(header.as_bytes());
    mac.update(b".");
    mac.update(claims.as_bytes());
    let signature = mac.finalize().into_bytes();
    Ok(URL_SAFE_NO_PAD.encode(signature))
}

fn evaluate_action(
    snapshot: &AuthorizationSnapshotClaim,
    action_bit: usize,
    scope_kind: Option<&str>,
    scope_id: Option<&str>,
) -> Result<(bool, Option<String>), DynError> {
    if Bitset::from_hex(&snapshot.tenant_bits, action_bit + 1)?.contains(action_bit) {
        return Ok((true, Some("tenant".to_owned())));
    }

    if let Some(scope_kind) = scope_kind {
        for scope in &snapshot.scopes {
            if scope.kind != scope_kind {
                continue;
            }

            let id_matches = match (scope.id.as_deref(), scope_id) {
                (None, _) => true,
                (Some(left), Some(right)) => left == right,
                _ => false,
            };

            if id_matches && Bitset::from_hex(&scope.bits, action_bit + 1)?.contains(action_bit) {
                let matched_scope = scope
                    .id
                    .as_ref()
                    .map(|id| format!("{scope_kind}:{id}"))
                    .unwrap_or_else(|| format!("{scope_kind}:*"));
                return Ok((true, Some(matched_scope)));
            }
        }
    }

    Ok((false, None))
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
