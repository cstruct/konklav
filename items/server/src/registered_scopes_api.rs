//! The control-plane surface for registered scopes: recording which tenant
//! and containing scopes a relying system's object belongs to, so
//! requirements can name the object alone. Records are read on the
//! relying surface.

use axum::extract::{Path, State};
use axum::routing::{post, put};
use axum::{Json, Router};
use diesel_async::AsyncConnection;
use konklav_authz::Scope;
use konklav_core::TenantId;
use konklav_store::events;
use konklav_store::registered_scopes::{self, Change, RegisteredScope};
use serde::{Deserialize, Serialize};

use crate::control_api::{Written, guard};
use crate::error::{ApiError, ApiJson};
use crate::{AppState, capabilities};

// r[impl authz.registered.capability]
pub fn routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/registered-scopes/{kind}/{id}", put(record).delete(remove))
        .route("/registered-scopes", post(batch))
        .route_layer(guard(state, capabilities::SCOPES_REGISTER))
}

#[derive(Deserialize)]
struct RecordBody {
    tenant: TenantId,
    #[serde(default)]
    containers: Vec<Scope>,
}

/// Applies `changes` in a transaction of its own, with the write cursor.
async fn apply(
    state: &AppState,
    changes: &[Change],
) -> Result<(Vec<Option<RegisteredScope>>, Option<konklav_core::Cursor>), ApiError> {
    let mut conn = state.pool.get().await?;
    conn.transaction::<_, ApiError, _>(async |conn| {
        let scopes = registered_scopes::apply(conn, changes).await?;
        Ok((scopes, events::last_in_transaction(conn).await?))
    })
    .await
}

/// `PUT /v1/registered-scopes/{kind}/{id}`: records the scope in a tenant,
/// or replaces its containing scopes.
async fn record(
    State(state): State<AppState>,
    Path((kind, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<RecordBody>,
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

#[derive(Deserialize)]
struct BatchBody {
    changes: Vec<Change>,
}

#[derive(Serialize)]
struct BatchResult {
    /// Each change's scope afterwards, in order; `null` for removing an
    /// unknown scope.
    scopes: Vec<Option<RegisteredScope>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<konklav_core::Cursor>,
}

/// `POST /v1/registered-scopes` with `{"changes": [...]}`: records and
/// removes up to 1000 scopes, all or nothing.
// r[impl authz.registered.batch]
async fn batch(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<BatchBody>,
) -> Result<Json<BatchResult>, ApiError> {
    let (scopes, cursor) = apply(&state, &body.changes).await?;
    Ok(Json(BatchResult { scopes, cursor }))
}
