//! Access requests: a signed-in person asks for a membership in a tenant
//! that takes requests, and an operator on the control plane, or a member
//! of the tenant holding `konklav:tenant:admit` there, approves (creating
//! the membership) or denies it. Relying systems learn of requests
//! from `access_request.changed` on the change feed, to tell whoever
//! decides.
//!
//! On the subject-facing surface, a subject has at most one request per
//! tenant that matters, at `/v1/tenants/{id}/access-request`: `GET` its
//! latest, `POST` to ask, `DELETE` to withdraw a pending one.

use std::collections::HashSet;

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use diesel_async::AsyncConnection;
use konklav_api::{
    self as api, AccessRequestPage, AccessRequestQuery, ApproveAccessRequest, Written,
};
use konklav_core::{MembershipId, SubjectId, TenantId};
use konklav_store::access_requests::{self, AccessRequest, AccessRequestState, Filter};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::{Connection, compile_input, events, memberships, roles, tenants};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::capabilities::{self, Operator};
use crate::control_api::{created_status, parse_id};
use crate::db::Db;
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::{AppState, import};

/// Which tenants take requests, from `access_requests` in the
/// configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Tenant ids and keys; `None` when every active tenant takes requests.
    pub tenants: Option<HashSet<tenants::Reference>>,
    /// How long after a denial the subject may ask the same tenant again.
    pub retry_after_denial: chrono::Duration,
}

impl Settings {
    /// Whether `tenant` takes requests: named by its id or its key, or
    /// every tenant does.
    // r[impl tenant.key.reference]
    #[must_use]
    pub fn takes(&self, tenant: &tenants::Tenant) -> bool {
        self.tenants.as_ref().is_none_or(|named| {
            named.contains(&tenants::Reference::Id(tenant.id))
                || tenant
                    .key
                    .as_ref()
                    .is_some_and(|key| named.contains(&tenants::Reference::Key(key.clone())))
        })
    }
}

/// A subject's own request for a tenant; and, for a member holding
/// `konklav:tenant:admit` there, the tenant's requests to decide.
pub fn subject_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/tenants/{id}/access-request",
            get(own_request).post(ask).delete(withdraw),
        )
        .route("/tenants/{id}/access-requests", get(tenant_requests))
        .route(
            "/tenants/{id}/access-requests/{request}/approve",
            post(tenant_approve),
        )
        .route(
            "/tenants/{id}/access-requests/{request}/deny",
            post(tenant_deny),
        )
}

/// Reading and deciding requests on the control plane.
pub(crate) fn control() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_access_requests))
        .routes(routes!(get_access_request))
        .routes(routes!(approve_access_request))
        .routes(routes!(deny_access_request))
}

fn transport(request: &AccessRequest) -> api::AccessRequest {
    api::AccessRequest {
        id: request.id,
        subject_id: request.subject_id,
        tenant_id: request.tenant_id,
        state: match request.state {
            AccessRequestState::Pending => api::AccessRequestState::Pending,
            AccessRequestState::Approved => api::AccessRequestState::Approved,
            AccessRequestState::Denied => api::AccessRequestState::Denied,
            AccessRequestState::Withdrawn => api::AccessRequestState::Withdrawn,
        },
        membership_id: request.membership_id,
        created_at: request.created_at,
        decided_at: request.decided_at,
        decided_by: request.decided_by,
    }
}

// --- Subject-facing ---------------------------------------------------------

/// The same answer for every tenant a subject may not ask, so asking shows
/// nothing about tenants that take no requests.
// r[impl membership.access-request.disclosure]
fn refused() -> ApiError {
    ApiError::new(
        ErrorCode::Forbidden,
        "that tenant doesn't take access requests",
    )
}

/// The signed-in person and the tenant they name, when they may ask it.
async fn asker(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
    tenant: &str,
) -> Result<(konklav_core::SubjectId, TenantId), ApiError> {
    let session = crate::flows::own_session(state, conn, headers).await?;
    let settings = state.auth.access_requests.as_ref().ok_or_else(refused)?;
    let tenant = crate::tenant_refs::resolve(conn, tenant)
        .await?
        .ok_or_else(refused)?;
    let found = tenants::get(conn, tenant).await.map_err(|_| refused())?;
    if !settings.takes(&found) {
        return Err(refused());
    }
    let subject = subjects::get(conn, session.subject_id).await?;
    if subject.state != SubjectState::Active || subject.kind != SubjectKind::Human {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "only people can ask for access",
        ));
    }
    Ok((subject.id, tenant))
}

/// `GET /v1/tenants/{id}/access-request`: the caller's latest request for
/// the tenant.
async fn own_request(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<api::AccessRequest>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (subject, tenant) = asker(&state, &mut conn, &headers, &tenant).await?;
    let latest = access_requests::list(
        &mut conn,
        Filter {
            tenant: Some(tenant),
            subject: Some(subject),
            state: None,
        },
        None,
        1,
    )
    .await?;
    latest
        .into_iter()
        .next()
        .map(|request| Json(transport(&request)))
        .ok_or_else(|| ApiError::not_found("access request"))
}

/// `POST /v1/tenants/{id}/access-request`: asks for a membership. Answers
/// 201 with a new request, or 200 with the one already pending.
// r[impl membership.access-request]
// r[impl membership.access-request.retry]
async fn ask(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let (subject, tenant) = asker(&state, &mut conn, &headers, &tenant).await?;
    let retry_after = state
        .auth
        .access_requests
        .as_ref()
        .map(|settings| settings.retry_after_denial)
        .unwrap_or_default();
    let (request, created) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let found = tenants::get(conn, tenant).await.map_err(|_| refused())?;
            if found.state != tenants::TenantState::Active {
                return Err(refused());
            }
            if memberships::find_active(conn, subject, tenant)
                .await?
                .is_some()
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "already a member of that tenant",
                ));
            }
            if let Some(pending) = access_requests::find_pending(conn, subject, tenant).await? {
                return Ok((pending, false));
            }
            if let Some(denied) = access_requests::last_denied(conn, subject, tenant).await?
                && let Some(again) = denied.checked_add_signed(retry_after)
                && again > Utc::now()
            {
                return Err(ApiError::new(
                    ErrorCode::Forbidden,
                    format!(
                        "the last request was denied; ask again after {}",
                        again.to_rfc3339()
                    ),
                ));
            }
            Ok(access_requests::create(conn, uuid::Uuid::now_v7(), subject, tenant).await?)
        })
        .await?;
    Ok((created_status(created), Json(transport(&request))).into_response())
}

/// `DELETE /v1/tenants/{id}/access-request`: withdraws the caller's
/// pending request.
// r[impl membership.access-request.decision]
async fn withdraw(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<api::AccessRequest>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (subject, tenant) = asker(&state, &mut conn, &headers, &tenant).await?;
    let pending = access_requests::find_pending(&mut conn, subject, tenant)
        .await?
        .ok_or_else(|| ApiError::not_found("pending access request"))?;
    let withdrawn = access_requests::decide(
        &mut conn,
        pending.id,
        AccessRequestState::Withdrawn,
        None,
        Some(subject),
    )
    .await?
    .ok_or_else(|| ApiError::not_found("pending access request"))?;
    Ok(Json(transport(&withdrawn)))
}

// --- Control plane ----------------------------------------------------------

fn parse_request_id(value: &str) -> Result<uuid::Uuid, ApiError> {
    parse_id(value, "access request id")
}

async fn find(conn: &mut Connection, id: uuid::Uuid) -> Result<AccessRequest, ApiError> {
    access_requests::get(conn, id)
        .await
        .map_err(|_| ApiError::not_found("access request"))
}

fn store_state(state: api::AccessRequestState) -> AccessRequestState {
    match state {
        api::AccessRequestState::Pending => AccessRequestState::Pending,
        api::AccessRequestState::Approved => AccessRequestState::Approved,
        api::AccessRequestState::Denied => AccessRequestState::Denied,
        api::AccessRequestState::Withdrawn => AccessRequestState::Withdrawn,
    }
}

/// A page of the requests `filter` matches, newest first.
async fn page(
    conn: &mut Connection,
    filter: Filter,
    before: Option<uuid::Uuid>,
    limit: Option<i64>,
) -> Result<AccessRequestPage, ApiError> {
    let limit = limit.unwrap_or(50).clamp(1, 500);
    let found = access_requests::list(conn, filter, before, limit).await?;
    let next = (i64::try_from(found.len()) == Ok(limit))
        .then(|| found.last().map(|request| request.id))
        .flatten();
    Ok(AccessRequestPage {
        access_requests: found
            .into_iter()
            .map(|request| transport(&request))
            .collect(),
        next,
    })
}

/// Lists access requests, newest first.
///
/// Optionally only those for one tenant, from one subject, or in one state,
/// such as the pending ones to decide.
#[utoipa::path(get, path = "/access-requests", tag = "access-requests", params(AccessRequestQuery),
    responses((status = 200, body = AccessRequestPage)))]
async fn list_access_requests(
    db: Db,
    Query(query): Query<AccessRequestQuery>,
) -> Result<Json<AccessRequestPage>, ApiError> {
    let mut conn = db.get().await?;
    let filter = Filter {
        tenant: crate::tenant_refs::require_some(&mut conn, query.tenant.as_deref()).await?,
        subject: query.subject,
        state: query.state.map(store_state),
    };
    Ok(Json(
        page(&mut conn, filter, query.before, query.limit).await?,
    ))
}

/// Gets an access request.
#[utoipa::path(get, path = "/access-requests/{id}", tag = "access-requests",
    params(("id" = uuid::Uuid, Path)),
    responses((status = 200, body = api::AccessRequest)))]
async fn get_access_request(
    db: Db,
    Path(id): Path<String>,
) -> Result<Json<api::AccessRequest>, ApiError> {
    let id = parse_request_id(&id)?;
    let mut conn = db.get().await?;
    Ok(Json(transport(&find(&mut conn, id).await?)))
}

/// Why a request decided otherwise can't be decided now.
fn decided_otherwise(request: &AccessRequest) -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        format!("the access request is {}", request.state.as_str()),
    )
}

/// Who decides a request, which bounds the roles they may give.
#[derive(Clone, Copy, Debug)]
enum Decider {
    /// An operator with `konklav:tenants:manage` on the control plane.
    Operator(Operator),
    /// A member of the request's tenant holding `konklav:tenant:admit`
    /// there, on the subject-facing surface.
    Member(SubjectId),
}

impl Decider {
    fn subject(self) -> Option<SubjectId> {
        match self {
            Self::Operator(operator) => operator.subject,
            Self::Member(subject) => Some(subject),
        }
    }
}

/// The pending request `id`, when `decider` may decide it: in `tenant`
/// when given (else not found), and not their own. A request already
/// decided `wanted` comes back as `Err(Ok(request))`, to answer as the
/// first time.
async fn decidable(
    conn: &mut Connection,
    id: uuid::Uuid,
    tenant: Option<TenantId>,
    decider: Decider,
    wanted: AccessRequestState,
) -> Result<Result<AccessRequest, AccessRequest>, ApiError> {
    let request = find(conn, id).await?;
    if tenant.is_some_and(|tenant| tenant != request.tenant_id) {
        return Err(ApiError::not_found("access request"));
    }
    // r[impl membership.access-request.tenant]
    if decider.subject() == Some(request.subject_id) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "no one may decide their own access request",
        ));
    }
    if request.state == wanted {
        return Ok(Err(request));
    }
    if !request.is_pending() {
        return Err(decided_otherwise(&request));
    }
    Ok(Ok(request))
}

/// Checks the roles an approval gives. An operator giving a role that names
/// a `konklav:` action needs `konklav:control:all`, as assigning it would;
/// a member gives only roles their membership holds tenant-wide, and none
/// naming a `konklav:` action.
async fn check_roles(
    conn: &mut Connection,
    tenant: TenantId,
    keys: &[String],
    decider: Decider,
) -> Result<(), ApiError> {
    let held = match decider {
        Decider::Operator(_) => None,
        Decider::Member(member) => Some(crate::invites::held_roles(conn, member, tenant).await?),
    };
    for key in keys {
        let role = roles::get(conn, tenant, key)
            .await
            .map_err(|_| ApiError::not_found("role"))?;
        let names_capability = capabilities::named_by_role(conn, &role).await?;
        match (decider, &held) {
            // r[impl authz.control-plane.escalation]
            (Decider::Operator(operator), _) if names_capability => {
                operator.require_all("giving a role that names a konklav: action")?;
            }
            // r[impl membership.access-request.tenant]
            (Decider::Member(_), Some(held)) if !held.contains(&role.id) => {
                return Err(ApiError::new(
                    ErrorCode::Forbidden,
                    format!("you can only admit others into roles you hold, and not `{key}`"),
                ));
            }
            (Decider::Member(_), _) if names_capability => {
                return Err(ApiError::invalid_request(format!(
                    "role `{key}` names a konklav: action, which a member's approval can't give"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Approves request `id`, as [`approve_access_request`] describes.
// r[impl membership.access-request.decision]
// r[impl membership.access-request.decider]
async fn approve(
    db: Db,
    id: uuid::Uuid,
    tenant: Option<TenantId>,
    body: &ApproveAccessRequest,
    decider: Decider,
) -> Result<Json<Written<api::AccessRequest>>, ApiError> {
    let mut conn = db.get().await?;
    let (request, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let request =
                match decidable(conn, id, tenant, decider, AccessRequestState::Approved).await? {
                    Ok(pending) => pending,
                    Err(approved) => return Ok((approved, None)),
                };
            check_roles(conn, request.tenant_id, &body.roles, decider).await?;
            let active =
                memberships::find_active(conn, request.subject_id, request.tenant_id).await?;
            let membership = match (body.membership, active) {
                (Some(named), Some(active)) if named != active.id => {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "the subject is already a member of the tenant",
                    ));
                }
                (_, Some(active)) => active.id,
                (named, None) => {
                    import::create_membership(
                        conn,
                        named.unwrap_or_else(MembershipId::new_v7),
                        request.subject_id,
                        request.tenant_id,
                        &body.facts,
                        &body.metadata,
                    )
                    .await?
                    .0
                    .id
                }
            };
            for role in &body.roles {
                import::assign_membership_role(conn, None, membership, role, None).await?;
            }
            let approved = access_requests::decide(
                conn,
                id,
                AccessRequestState::Approved,
                Some(membership),
                decider.subject(),
            )
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::Conflict, "decided meanwhile"))?;
            Ok((approved, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: transport(&request),
        cursor,
    }))
}

/// Denies request `id`, as [`deny_access_request`] describes.
// r[impl membership.access-request.decision]
// r[impl membership.access-request.decider]
async fn deny(
    db: Db,
    id: uuid::Uuid,
    tenant: Option<TenantId>,
    decider: Decider,
) -> Result<Json<Written<api::AccessRequest>>, ApiError> {
    let mut conn = db.get().await?;
    let (request, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            if let Err(denied) =
                decidable(conn, id, tenant, decider, AccessRequestState::Denied).await?
            {
                return Ok((denied, None));
            }
            let denied = access_requests::decide(
                conn,
                id,
                AccessRequestState::Denied,
                None,
                decider.subject(),
            )
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::Conflict, "decided meanwhile"))?;
            Ok((denied, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: transport(&request),
        cursor,
    }))
}

/// Approves an access request: the subject becomes a member of the tenant,
/// with the facts and roles given, in one transaction.
///
/// When the subject has become a member meanwhile, the approval records
/// that membership and creates none, but still assigns the roles. Giving a
/// role that names a `konklav:` action needs `konklav:control:all`. No one
/// may approve their own request. Approving an approved request again
/// answers 200 with it and changes nothing; a denied or withdrawn one can't
/// be approved.
#[utoipa::path(post, path = "/access-requests/{id}/approve", tag = "access-requests",
    params(("id" = uuid::Uuid, Path)),
    request_body = ApproveAccessRequest,
    responses(
        (status = 200, body = Written<api::AccessRequest>),
        (status = 409, description = "Denied or withdrawn already", body = konklav_api::ErrorResponse),
    ))]
async fn approve_access_request(
    db: Db,
    Extension(operator): Extension<Operator>,
    limit: crate::metadata::Limit,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ApproveAccessRequest>,
) -> Result<Json<Written<api::AccessRequest>>, ApiError> {
    let id = parse_request_id(&id)?;
    limit.check(&body.metadata)?;
    approve(db, id, None, &body, Decider::Operator(operator)).await
}

/// Denies an access request.
///
/// The subject may ask the same tenant again only after
/// `access_requests.retry_after_denial_hours`. No one may deny their own
/// request. Denying a denied request again answers 200 with it; an approved
/// or withdrawn one can't be denied.
#[utoipa::path(post, path = "/access-requests/{id}/deny", tag = "access-requests",
    params(("id" = uuid::Uuid, Path)),
    responses(
        (status = 200, body = Written<api::AccessRequest>),
        (status = 409, description = "Approved or withdrawn already", body = konklav_api::ErrorResponse),
    ))]
async fn deny_access_request(
    db: Db,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
) -> Result<Json<Written<api::AccessRequest>>, ApiError> {
    let id = parse_request_id(&id)?;
    deny(db, id, None, Decider::Operator(operator)).await
}

// --- Deciding as a member of the tenant (subject-facing) ---------------------

/// The calling member and the tenant in the path, if the member's own full
/// session holds `konklav:tenant:admit` tenant-wide there, or globally.
// r[impl membership.access-request.tenant]
// r[impl authz.tenant-capability]
async fn admitter(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
    tenant: &str,
) -> Result<(SubjectId, TenantId), ApiError> {
    let caller = crate::flows::own_session(state, conn, headers)
        .await?
        .subject_id;
    let refused = || {
        ApiError::new(
            ErrorCode::Forbidden,
            "deciding access requests to this tenant needs `konklav:tenant:admit` there",
        )
    };
    let tenant = crate::tenant_refs::resolve(conn, tenant)
        .await?
        .ok_or_else(refused)?;
    let entitlements = compile_input::load(conn, caller, Some(tenant))
        .await?
        .compile();
    if entitlements.tenant.contains(capabilities::TENANT_ADMIT)
        || entitlements.global.contains(capabilities::TENANT_ADMIT)
    {
        Ok((caller, tenant))
    } else {
        Err(refused())
    }
}

/// Which of a tenant's requests a member lists.
#[derive(Debug, Default, Deserialize)]
struct TenantQuery {
    state: Option<api::AccessRequestState>,
    before: Option<uuid::Uuid>,
    limit: Option<i64>,
}

/// `GET /v1/tenants/{id}/access-requests`: the tenant's requests, newest
/// first, optionally in one state.
async fn tenant_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<AccessRequestPage>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (_, tenant) = admitter(&state, &mut conn, &headers, &tenant).await?;
    let filter = Filter {
        tenant: Some(tenant),
        subject: None,
        state: query.state.map(store_state),
    };
    Ok(Json(
        page(&mut conn, filter, query.before, query.limit).await?,
    ))
}

/// `POST /v1/tenants/{id}/access-requests/{request}/approve`: approves a
/// request to the tenant, giving only roles the member holds there.
async fn tenant_approve(
    State(state): State<AppState>,
    db: Db,
    limit: crate::metadata::Limit,
    headers: HeaderMap,
    Path((tenant, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<ApproveAccessRequest>,
) -> Result<Json<Written<api::AccessRequest>>, ApiError> {
    let (member, tenant) = {
        let mut conn = state.pool.get().await?;
        admitter(&state, &mut conn, &headers, &tenant).await?
    };
    let id = parse_request_id(&id)?;
    limit.check(&body.metadata)?;
    approve(db, id, Some(tenant), &body, Decider::Member(member)).await
}

/// `POST /v1/tenants/{id}/access-requests/{request}/deny`: denies a request
/// to the tenant.
async fn tenant_deny(
    State(state): State<AppState>,
    db: Db,
    headers: HeaderMap,
    Path((tenant, id)): Path<(String, String)>,
) -> Result<Json<Written<api::AccessRequest>>, ApiError> {
    let (member, tenant) = {
        let mut conn = state.pool.get().await?;
        admitter(&state, &mut conn, &headers, &tenant).await?
    };
    let id = parse_request_id(&id)?;
    deny(db, id, Some(tenant), Decider::Member(member)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(key: Option<&str>) -> tenants::Tenant {
        tenants::Tenant {
            id: TenantId::new_v7(),
            parent_id: Some(tenants::ROOT),
            state: tenants::TenantState::Active,
            facts: serde_json::json!({}),
            metadata: serde_json::json!({}),
            key: key.map(str::to_owned),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn listed_tenants_take_requests_unless_all_do() {
        let listed = tenant(None);
        let keyed = tenant(Some("acme"));
        let some = Settings {
            tenants: Some(HashSet::from([
                tenants::Reference::Id(listed.id),
                tenants::Reference::Key("acme".into()),
            ])),
            retry_after_denial: chrono::Duration::hours(1),
        };
        assert!(some.takes(&listed));
        assert!(some.takes(&keyed), "named by its key");
        assert!(!some.takes(&tenant(None)));
        assert!(!some.takes(&tenant(Some("other"))));
        let all = Settings {
            tenants: None,
            ..some
        };
        assert!(all.takes(&tenant(None)));
    }
}
