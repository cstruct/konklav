//! The control-plane surface for registered scopes: recording which tenant
//! and containing scopes a relying system's object belongs to, so
//! requirements can name the object alone. Records are read on the
//! relying surface.

use axum::Json;
use axum::extract::{Path, State};
use diesel_async::AsyncConnection;
use konklav_api::{
    RecordRegisteredScope, RegisteredScope, RegisteredScopeBatch, RegisteredScopeChanges,
};
use konklav_store::events;
use konklav_store::registered_scopes::{self, Change};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::control_api::Written;
use crate::error::{ApiError, ApiJson};
use crate::{AppState, transport};

/// Registered scopes, with the `OpenAPI` description of each route taken
/// from its handler's `#[utoipa::path]`.
pub(crate) fn registered_scopes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(record, remove))
        .routes(routes!(batch))
}

// r[impl authz.registered.capability]

/// Applies `changes` in a transaction of its own, with the write cursor.
async fn apply(
    state: &AppState,
    changes: &[Change],
) -> Result<(Vec<Option<RegisteredScope>>, Option<konklav_core::Cursor>), ApiError> {
    let mut conn = state.pool.get().await?;
    let (scopes, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let scopes = registered_scopes::apply(conn, changes).await?;
            Ok((scopes, events::last_in_transaction(conn).await?))
        })
        .await?;
    let scopes = scopes
        .into_iter()
        .map(|scope| scope.map(transport::registered_scope))
        .collect();
    Ok((scopes, cursor))
}

/// `PUT /v1/registered-scopes/{kind}/{id}`: records the scope in a tenant,
/// or replaces its containing scopes.
#[utoipa::path(put, path = "/registered-scopes/{kind}/{id}", operation_id = "record_registered_scope", tag = "registered-scopes",
    params(("kind" = String, Path, description = "A registered scope kind"), ("id" = String, Path)),
    request_body = RecordRegisteredScope,
    responses((status = 200, body = Written<RegisteredScope>)))]
async fn record(
    State(state): State<AppState>,
    Path((kind, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<RecordRegisteredScope>,
) -> Result<Json<Written<RegisteredScope>>, ApiError> {
    let (mut scopes, cursor) = apply(
        &state,
        &[Change::Record {
            kind,
            id,
            tenant: body.tenant,
            containers: body.containers,
        }],
    )
    .await?;
    let value = scopes
        .pop()
        .flatten()
        .ok_or_else(|| ApiError::not_found("registered scope"))?;
    Ok(Json(Written { value, cursor }))
}

/// `DELETE /v1/registered-scopes/{kind}/{id}`: removes the scope. It keeps
/// its tenant, so it can only be recorded again in the same one.
#[utoipa::path(delete, path = "/registered-scopes/{kind}/{id}", operation_id = "remove_registered_scope", tag = "registered-scopes",
    params(("kind" = String, Path, description = "A registered scope kind"), ("id" = String, Path)),
    responses((status = 200, body = Written<RegisteredScope>)))]
async fn remove(
    State(state): State<AppState>,
    Path((kind, id)): Path<(String, String)>,
) -> Result<Json<Written<RegisteredScope>>, ApiError> {
    let (mut scopes, cursor) = apply(&state, &[Change::Remove { kind, id }]).await?;
    let value = scopes
        .pop()
        .flatten()
        .ok_or_else(|| ApiError::not_found("registered scope"))?;
    Ok(Json(Written { value, cursor }))
}

/// `POST /v1/registered-scopes` with `{"changes": [...]}`: records and
/// removes up to 1000 scopes, all or nothing.
// r[impl authz.registered.batch]
#[utoipa::path(post, path = "/registered-scopes", operation_id = "change_registered_scopes", tag = "registered-scopes",
    request_body = RegisteredScopeChanges,
    responses((status = 200, body = RegisteredScopeBatch)))]
async fn batch(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<RegisteredScopeChanges>,
) -> Result<Json<RegisteredScopeBatch>, ApiError> {
    let changes: Vec<Change> = body
        .changes
        .into_iter()
        .map(transport::registered_scope_change)
        .collect();
    let (scopes, cursor) = apply(&state, &changes).await?;
    Ok(Json(RegisteredScopeBatch { scopes, cursor }))
}
