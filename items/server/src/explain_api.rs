//! Explaining decisions in the control plane: why a subject would be
//! allowed or denied an operation, check by check and action by action,
//! now or, with history enabled, as of a past time.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, SecondsFormat, Utc};
use konklav_api::ExplainDecision;
use konklav_authz::{Check, DecisionExplanation, ExplainInput, Requirements, SessionContext};
use konklav_core::{SubjectId, TenantId};
use konklav_store::compile_input::{self, CompileInput};
use konklav_store::sessions::{self, Stage};
use konklav_store::subjects::{self, SubjectState};
use konklav_store::tenants::{self, TenantState};
use konklav_store::{Connection, history, memberships, registered_scopes, shares};
use konklav_token::{AccessClaims, TokenKind};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::AppState;
use crate::control_api::parse_id;
use crate::error::{ApiError, ApiJson};
use crate::import::not_found_as;

/// Explaining decisions, with the `OpenAPI` description taken from the
/// handler's `#[utoipa::path]`.
pub(crate) fn explain() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(explain_decision))
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

/// What an explanation reads from the store, from one snapshot.
struct Gathered {
    checks: Vec<Check>,
    input: CompileInput,
    offered: Vec<konklav_authz::Share>,
    registered: konklav_authz::RegisteredScopes,
}

async fn gather(
    conn: &mut Connection,
    subject: SubjectId,
    tenant: Option<TenantId>,
    requirements: &Requirements,
) -> Result<Gathered, ApiError> {
    let checks = activity_checks(conn, subject, tenant).await?;
    let input = compile_input::read(conn, subject, tenant).await?;
    let offered = match tenant {
        Some(tenant) => shares::offered_for(conn, tenant).await?,
        None => Vec::new(),
    };
    let registered =
        registered_scopes::for_requirements(conn, input.document.registered_kinds(), requirements)
            .await?;
    Ok(Gathered {
        checks,
        input,
        offered,
        registered,
    })
}

/// Refuses `at` unless history reaches it.
// r[impl authz.explain.at]
async fn check_reach(
    conn: &mut Connection,
    at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let Some(status) = history::status(conn).await? else {
        return Err(ApiError::invalid_request(
            "history isn't enabled, so decisions can only be explained as of now",
        ));
    };
    if at > now {
        return Err(ApiError::invalid_request("`at` is in the future"));
    }
    let horizon = status.horizon(now);
    if at < horizon {
        return Err(ApiError::invalid_request(format!(
            "history reaches back only to {}",
            horizon.to_rfc3339_opts(SecondsFormat::Secs, true)
        )));
    }
    Ok(())
}

/// `POST /v1/subjects/{id}/explain-decision`
// r[impl authz.explain.decision]
// r[impl authz.explain.checks]
#[utoipa::path(post, path = "/subjects/{id}/explain-decision", tag = "explain",
    params(("id" = SubjectId, Path)),
    request_body = ExplainDecision,
    responses((status = 200, body = DecisionExplanation)))]
async fn explain_decision(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ExplainDecision>,
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
    if body.at.is_some() && body.session.is_some() {
        return Err(ApiError::invalid_request(
            "`at` can't be combined with a session: history doesn't keep sessions",
        ));
    }
    let mut conn = state.pool.get().await?;
    let now = Utc::now();
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

    let Gathered {
        checks,
        input,
        offered,
        registered,
    } = match body.at {
        None => {
            conn.build_transaction()
                .read_only()
                .repeatable_read()
                .run::<_, ApiError, _>(async |conn| {
                    gather(conn, subject, tenant, &body.requirements).await
                })
                .await?
        }
        Some(at) => {
            check_reach(&mut conn, at, now).await?;
            // Not read-only: the shadow tables are created in it.
            conn.build_transaction()
                .repeatable_read()
                .run::<_, ApiError, _>(async |conn| {
                    history::shadow(conn, at).await?;
                    gather(conn, subject, tenant, &body.requirements).await
                })
                .await?
        }
    };
    let restrictive_flags = input.document.restrictive_flags();
    let claims = session.as_ref().map(|session| claims_of(&state, session));
    let context = session
        .as_ref()
        .zip(claims.as_ref())
        .map(|(session, claims)| SessionContext {
            claims,
            restrictive_flags: &restrictive_flags,
            current: session.is_active_at(now),
        });
    Ok(Json(konklav_authz::explain_decision(
        &ExplainInput {
            catalog: &input.catalog,
            assignments: &input.assignments,
            shares: &input.shares,
            offered: &offered,
            requirements: &body.requirements,
            registered: &registered,
            tenant,
            session: context,
            now: body.at.unwrap_or(now).timestamp(),
        },
        checks,
    )))
}
