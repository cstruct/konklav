//! The relying surface's authorization endpoints: entitlement sets and the
//! central check API. Callers authenticate as service principals.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use konklav_authz::{Decision, EntitlementSet, Requirements, compile, evaluate};
use konklav_core::{Cursor, SubjectId, TenantId};
use konklav_store::subjects::{self, SubjectKind};
use konklav_store::{Connection, compile_input, tenants};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::subject_api::{authenticate, verify_access_token};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/entitlements/{subject}", get(global_entitlements))
        .route("/entitlements/{subject}/{tenant}", get(tenant_entitlements))
        .route("/check", post(check))
}

/// Only service principals may use the relying surface.
pub(crate) async fn require_service(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
) -> Result<SubjectId, ApiError> {
    let (claims, _) = authenticate(state, conn, headers).await?;
    let caller = subjects::get(conn, claims.sub).await?;
    if caller.kind == SubjectKind::Service {
        Ok(caller.id)
    } else {
        Err(ApiError::new(
            ErrorCode::Forbidden,
            "only service principals can use the relying surface",
        ))
    }
}

async fn compile_for(
    conn: &mut Connection,
    subject: SubjectId,
    tenant: Option<TenantId>,
) -> Result<EntitlementSet, ApiError> {
    let input = compile_input::load(conn, subject, tenant).await?;
    Ok(EntitlementSet {
        subject_id: subject,
        tenant_id: tenant,
        revision: input.revision,
        entitlements: compile(&input.catalog, &input.assignments),
        restrictive_flags: input.document.restrictive_flags(),
    })
}

fn parse_subject(value: &str) -> Result<SubjectId, ApiError> {
    value
        .parse()
        .map_err(|_| ApiError::invalid_request("subject is not a valid identifier"))
}

/// `GET /v1/entitlements/{subject}`: global entitlements only.
async fn global_entitlements(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
) -> Result<Json<EntitlementSet>, ApiError> {
    let subject = parse_subject(&subject)?;
    let mut conn = state.pool.get().await?;
    require_service(&state, &mut conn, &headers).await?;
    Ok(Json(compile_for(&mut conn, subject, None).await?))
}

/// `GET /v1/entitlements/{subject}/{tenant}`
// r[impl authz.api.entitlements]
async fn tenant_entitlements(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((subject, tenant)): Path<(String, String)>,
) -> Result<Json<EntitlementSet>, ApiError> {
    let subject = parse_subject(&subject)?;
    let tenant = tenants::parse_reference(&tenant)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))?;
    let mut conn = state.pool.get().await?;
    require_service(&state, &mut conn, &headers).await?;
    Ok(Json(compile_for(&mut conn, subject, Some(tenant)).await?))
}

#[derive(Deserialize)]
struct CheckRequest {
    /// The access token presented to the relying system.
    token: String,
    #[serde(default)]
    requirements: Requirements,
}

#[derive(Serialize)]
struct CheckResponse {
    #[serde(flatten)]
    decision: Decision,
    revision: Option<Cursor>,
}

/// `POST /v1/check`: decides from current state, including whether the
/// token's session is still valid.
// r[impl authz.api.check]
// r[impl authz.api.check-equivalence]
async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<CheckRequest>,
) -> Result<Json<CheckResponse>, ApiError> {
    let mut conn = state.pool.get().await?;
    require_service(&state, &mut conn, &headers).await?;
    let (claims, _) = match verify_access_token(&state, &mut conn, &body.token).await {
        Ok(verified) => verified,
        Err(error)
            if matches!(
                error.code,
                ErrorCode::Unauthenticated | ErrorCode::SessionEnded
            ) =>
        {
            return Ok(Json(CheckResponse {
                decision: Decision::Deny {
                    reason: konklav_authz::DenyReason::InvalidToken,
                },
                revision: None,
            }));
        }
        Err(error) => return Err(error),
    };
    let set = compile_for(&mut conn, claims.sub, claims.tid).await?;
    let decision = evaluate(
        &body.requirements,
        &claims,
        &set.restrictive_flags,
        &set.entitlements,
        Utc::now().timestamp(),
    );
    Ok(Json(CheckResponse {
        decision,
        revision: Some(set.revision),
    }))
}
