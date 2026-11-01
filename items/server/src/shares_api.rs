//! The control-plane surface for shares: offering one tenant's scope to
//! another, accepting it for the recipient, and revoking it.
//!
//! Konklav has no tenant administrators of its own, so the relying system
//! calls these on behalf of the owner's and the recipient's administrators.
//! The two steps record that both sides agreed.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use diesel_async::AsyncConnection;
use konklav_core::ShareId;
use konklav_store::catalog::FactTarget;
use konklav_store::shares::{self, Share, ShareTerms, Side};
use konklav_store::{events, tenants};
use serde::{Deserialize, Serialize};

use crate::control_api::{Written, guard, parse_id};
use crate::error::{ApiError, ApiJson};
use crate::import::{not_found_as, validate_facts};
use crate::{AppState, capabilities};

pub fn routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/shares/{id}", put(offer).get(get_share))
        .route("/shares/{id}/accept", post(accept))
        .route("/shares/{id}/revoke", post(revoke))
        .route("/tenants/{id}/shares", get(list))
        .route_layer(guard(state, capabilities::AUTHZ))
}

fn share_id(value: &str) -> Result<ShareId, ApiError> {
    parse_id(value, "share id")
}

/// `PUT /v1/shares/{id}`: offers a share, or changes the terms of one that
/// isn't revoked, which offers it again.
// r[impl authz.share.shape]
// r[impl authz.share.attributes]
async fn offer(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(terms): ApiJson<ShareTerms>,
) -> Result<Json<Written<Share>>, ApiError> {
    let id = share_id(&id)?;
    if terms.owner == terms.recipient {
        return Err(ApiError::invalid_request(
            "a tenant can't share with itself",
        ));
    }
    if let Some(action) = terms
        .actions
        .iter()
        .find(|action| action.starts_with(konklav_store::catalog::CAPABILITY_PREFIX))
    {
        return Err(ApiError::invalid_request(format!(
            "control-plane capabilities can't be shared (`{action}`)"
        )));
    }
    if let (Some(from), Some(until)) = (terms.valid_from, terms.valid_until)
        && from >= until
    {
        return Err(ApiError::invalid_request(
            "valid_from must be before valid_until",
        ));
    }
    let mut conn = state.pool.get().await?;
    let (share, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            tenants::get(conn, terms.owner)
                .await
                .map_err(not_found_as("owner tenant"))?;
            tenants::get(conn, terms.recipient)
                .await
                .map_err(not_found_as("recipient tenant"))?;
            validate_facts(
                conn,
                FactTarget::Share,
                &serde_json::Value::Object(terms.attributes.clone()),
            )
            .await?;
            let share = shares::offer(conn, id, &terms).await?;
            Ok((share, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: share,
        cursor,
    }))
}

async fn get_share(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Share>, ApiError> {
    let id = share_id(&id)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(
        shares::get(&mut conn, id)
            .await
            .map_err(not_found_as("share"))?,
    ))
}

/// `POST /v1/shares/{id}/accept`, for the recipient tenant.
// r[impl authz.share.acceptance]
async fn accept(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Written<Share>>, ApiError> {
    let id = share_id(&id)?;
    let mut conn = state.pool.get().await?;
    let (share, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let share = shares::accept(conn, id)
                .await
                .map_err(not_found_as("share"))?;
            Ok((share, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: share,
        cursor,
    }))
}

#[derive(Deserialize)]
struct RevokeBody {
    /// Which side revokes.
    by: Side,
}

/// `POST /v1/shares/{id}/revoke`, by either side.
// r[impl authz.share.acceptance]
async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<RevokeBody>,
) -> Result<Json<Written<Share>>, ApiError> {
    let id = share_id(&id)?;
    let mut conn = state.pool.get().await?;
    let (share, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let share = shares::revoke(conn, id, body.by)
                .await
                .map_err(not_found_as("share"))?;
            Ok((share, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: share,
        cursor,
    }))
}

#[derive(Deserialize)]
struct ListQuery {
    side: Option<Side>,
}

#[derive(Serialize)]
struct ShareList {
    shares: Vec<Share>,
}

/// `GET /v1/tenants/{id}/shares?side=owner|recipient`
async fn list(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ShareList>, ApiError> {
    let tenant = tenants::parse_reference(&tenant)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))?;
    let mut conn = state.pool.get().await?;
    Ok(Json(ShareList {
        shares: shares::list(&mut conn, tenant, query.side).await?,
    }))
}
