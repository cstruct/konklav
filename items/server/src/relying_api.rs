//! The relying surface's authorization endpoints: entitlement sets and the
//! central check API, and the list of erased subjects. Callers authenticate
//! as service principals.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use konklav_authz::Scope;
use konklav_authz::{
    Decision, EntitlementSet, Requirements, RouteAuthority, evaluate_with_route_authority,
};
use konklav_core::{Cursor, SubjectId, TenantId};
use konklav_store::registered_scopes::{self, RegisteredScope};
use konklav_store::subjects::{self, SubjectKind};
use konklav_store::{Connection, StoreError, compile_input, tenants};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::subject_api::{authenticate, verify_access_token_for};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/entitlements/{subject}", get(global_entitlements))
        .route("/entitlements/{subject}/{tenant}", get(tenant_entitlements))
        .route("/check", post(check))
        .route("/registered-scopes/{kind}/{id}", get(registered_scope))
        .route("/erased-subjects", get(erased_subjects))
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
        entitlements: input.compile(),
        restrictive_flags: input.document.restrictive_flags(),
        registered_kinds: input.document.registered_kinds(),
        confinements: input.confinements(),
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
    /// The audiences the relying system accepts; Konklav's own when absent.
    audiences: Option<Vec<String>>,
    /// The route authority of the request's allowed route decision, for a
    /// later decision of the same request; absent for a route decision.
    // r[impl authz.api.check-route-authority]
    route_authority: Option<RouteAuthority>,
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
// r[impl authz.api.check-route-authority]
// r[depends item.authz.single-evaluator]
async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<CheckRequest>,
) -> Result<Json<CheckResponse>, ApiError> {
    let mut conn = state.pool.get().await?;
    require_service(&state, &mut conn, &headers).await?;
    // A sender-constrained token is decided without its DPoP proof: the
    // relying system calling this has checked the proof already.
    // r[impl relying.verify.dpop-before-check]
    // r[impl authz.api.check-audiences]
    let audiences = body
        .audiences
        .unwrap_or_else(|| vec![state.auth.audience.clone()]);
    let verified = verify_access_token_for(&state, &mut conn, &body.token, &audiences).await;
    let (claims, _) = match verified {
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
    let registered = registered_scopes::for_requirements(
        &mut conn,
        set.registered_kinds.clone(),
        &body.requirements,
    )
    .await?;
    let decision = evaluate_with_route_authority(
        &body.requirements,
        body.route_authority.as_ref(),
        &claims,
        &set.restrictive_flags,
        &set.confinements,
        &set.entitlements,
        &registered,
        Utc::now().timestamp(),
    );
    Ok(Json(CheckResponse {
        decision,
        revision: Some(set.revision),
    }))
}

/// `GET /v1/registered-scopes/{kind}/{id}`: a registered scope's tenant,
/// state and containing scopes, so a relying core can decide requirements
/// that name it.
// r[impl authz.registered.api]
async fn registered_scope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, String)>,
) -> Result<Json<RegisteredScope>, ApiError> {
    let mut conn = state.pool.get().await?;
    require_service(&state, &mut conn, &headers).await?;
    Ok(Json(
        registered_scopes::get(&mut conn, &Scope { kind, id }).await?,
    ))
}

#[derive(Deserialize)]
struct ErasedQuery {
    /// Only subjects erased at or after this time, in seconds since the
    /// epoch; every erased subject when absent.
    since: Option<i64>,
    /// The `next` of the previous page.
    after: Option<SubjectId>,
    limit: Option<i64>,
}

/// One erased subject, in the form of a `subject.erased` event's payload.
#[derive(Serialize)]
struct ErasedSubject {
    subject: SubjectId,
    /// Seconds since the epoch.
    erased_at: i64,
}

#[derive(Serialize)]
struct ErasedPage {
    subjects: Vec<ErasedSubject>,
    /// Pass as `after`, with the same `since`, for the next page; absent on
    /// the last.
    next: Option<SubjectId>,
}

/// `GET /v1/erased-subjects`: the erased subjects in the order they were
/// erased, so a relying system that missed `subject.erased` events can
/// catch up. Unlike the feed, the list is never pruned.
// r[impl subject.erasure.list]
async fn erased_subjects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ErasedQuery>,
) -> Result<Json<ErasedPage>, ApiError> {
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let since = query
        .since
        .map(|since| {
            DateTime::<Utc>::from_timestamp(since, 0)
                .ok_or_else(|| ApiError::invalid_request("`since` is not a valid time"))
        })
        .transpose()?;
    let mut conn = state.pool.get().await?;
    require_service(&state, &mut conn, &headers).await?;
    let erased = match subjects::erased(&mut conn, since, query.after, limit).await {
        Err(StoreError::NotFound) => {
            return Err(ApiError::invalid_request(
                "`after` is not the id of an erased subject",
            ));
        }
        other => other?,
    };
    let next = (i64::try_from(erased.len()) == Ok(limit))
        .then(|| erased.last().map(|last| last.id))
        .flatten();
    Ok(Json(ErasedPage {
        subjects: erased
            .iter()
            .map(|erased| ErasedSubject {
                subject: erased.id,
                erased_at: erased.erased_at.timestamp(),
            })
            .collect(),
        next,
    }))
}
