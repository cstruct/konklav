//! Explaining decisions in the control plane: why a subject would be
//! allowed or denied an operation, check by check and action by action.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use konklav_authz::{
    Check, DecisionExplanation, ExplainInput, Requirements, SessionContext, explain_decision,
};
use konklav_core::{SessionId, SubjectId, TenantId};
use konklav_store::sessions::{self, Stage};
use konklav_store::subjects::{self, SubjectState};
use konklav_store::tenants::{self, TenantState};
use konklav_store::{Connection, compile_input, memberships, registered_scopes, shares};
use konklav_token::{AccessClaims, TokenKind};
use serde::Deserialize;

use crate::control_api::{guard, parse_id};
use crate::error::{ApiError, ApiJson};
use crate::import::not_found_as;
use crate::{AppState, capabilities};

pub fn routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/subjects/{id}/explain-decision", post(explain))
        .route_layer(guard(state, capabilities::AUTHZ))
}

#[derive(Deserialize)]
struct ExplainBody {
    /// The tenant to decide in; the session's when absent.
    #[serde(default)]
    tenant: Option<String>,
    /// One of the subject's sessions, to check authentication as its tokens
    /// would be checked.
    #[serde(default)]
    session: Option<SessionId>,
    #[serde(default)]
    requirements: Requirements,
}

/// Claims as an access token for `session` would carry them.
fn claims_of(state: &AppState, session: &sessions::Session) -> AccessClaims {
    let now = Utc::now().timestamp();
    AccessClaims {
        iss: state.auth.issuer.clone(),
        aud: state.auth.audience.clone(),
        sub: session.subject_id,
        jti: String::new(),
        iat: now,
        exp: now + state.auth.access_ttl.num_seconds(),
        knd: match session.stage {
            Stage::Partial => TokenKind::Partial,
            Stage::Identity => TokenKind::Identity,
            Stage::Tenant => TokenKind::Tenant,
        },
        sid: session.id,
        cid: None,
        sv: session.version,
        amr: session.amr.clone(),
        auth_time: session.auth_time.timestamp(),
        tid: session.tenant_id,
        mid: session.membership_id,
        sfl: session.flags.clone(),
        fct: BTreeMap::new(),
        act: None,
    }
}

/// Whether the subject, its membership in `tenant` and the tenant are
/// active: compilation silently drops what inactive ones contribute.
async fn activity_checks(
    conn: &mut Connection,
    subject: SubjectId,
    tenant: Option<TenantId>,
) -> Result<Vec<Check>, ApiError> {
    let principal = subjects::get(conn, subject)
        .await
        .map_err(not_found_as("subject"))?;
    let active = principal.state == SubjectState::Active;
    let mut checks = vec![Check::new(
        "subject_active",
        active,
        if active {
            "The subject is active."
        } else {
            "The subject is disabled, so it holds nothing."
        },
    )];
    if let Some(tenant) = tenant {
        let found = tenants::get(conn, tenant)
            .await
            .map_err(not_found_as("tenant"))?;
        let active = found.state == TenantState::Active;
        checks.push(Check::new(
            "tenant_active",
            active,
            if active {
                "The tenant is active."
            } else {
                "The tenant isn't active, so nothing is granted in it."
            },
        ));
        let member = memberships::find_active(conn, subject, tenant)
            .await?
            .is_some();
        checks.push(Check::new(
            "membership_active",
            member,
            if member {
                "The subject has an active membership in the tenant."
            } else {
                "The subject has no active membership in the tenant, so only global roles count."
            },
        ));
    }
    Ok(checks)
}

/// `POST /v1/subjects/{id}/explain-decision`
// r[impl authz.explain.decision]
// r[impl authz.explain.checks]
async fn explain(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ExplainBody>,
) -> Result<Json<DecisionExplanation>, ApiError> {
    let subject: SubjectId = parse_id(&id, "subject id")?;
    let mut tenant = body
        .tenant
        .as_deref()
        .map(|value| {
            tenants::parse_reference(value)
                .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))
        })
        .transpose()?;
    let mut conn = state.pool.get().await?;
    let session = match body.session {
        Some(id) => {
            let session = sessions::get(&mut conn, id)
                .await
                .map_err(not_found_as("session"))?;
            if session.subject_id != subject {
                return Err(ApiError::invalid_request(
                    "the session belongs to another subject",
                ));
            }
            match (tenant, session.tenant_id) {
                (None, selected) => tenant = selected,
                (Some(asked), selected) if Some(asked) != selected => {
                    return Err(ApiError::invalid_request(
                        "the session is for another tenant than the one given",
                    ));
                }
                _ => {}
            }
            Some(session)
        }
        None => None,
    };

    let checks = activity_checks(&mut conn, subject, tenant).await?;
    let input = compile_input::load(&mut conn, subject, tenant).await?;
    let offered = match tenant {
        Some(tenant) => shares::offered_for(&mut conn, tenant).await?,
        None => Vec::new(),
    };
    let restrictive_flags = input.document.restrictive_flags();
    let registered = registered_scopes::for_requirements(
        &mut conn,
        input.document.registered_kinds(),
        &body.requirements,
    )
    .await?;
    let now = Utc::now();
    let claims = session.as_ref().map(|session| claims_of(&state, session));
    let context = session
        .as_ref()
        .zip(claims.as_ref())
        .map(|(session, claims)| SessionContext {
            claims,
            restrictive_flags: &restrictive_flags,
            current: session.is_active_at(now),
        });
    Ok(Json(explain_decision(
        &ExplainInput {
            catalog: &input.catalog,
            assignments: &input.assignments,
            shares: &input.shares,
            offered: &offered,
            requirements: &body.requirements,
            registered: &registered,
            tenant,
            session: context,
            now: now.timestamp(),
        },
        checks,
    )))
}
