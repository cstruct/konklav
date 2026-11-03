//! The control-plane surface for shares: offering one tenant's scope to
//! another, accepting it for the recipient, and revoking it.
//!
//! Konklav has no tenant administrators of its own, so the relying system
//! calls these on behalf of the owner's and the recipient's administrators.
//! The two steps record that both sides agreed.

use axum::Json;
use axum::extract::{Path, Query, State};
use diesel_async::AsyncConnection;
use konklav_api::{RevokeShare, Share, ShareList, ShareQuery, ShareTerms};
use konklav_core::ShareId;
use konklav_store::catalog::FactTarget;
use konklav_store::shares;
use konklav_store::{events, tenants};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::control_api::{Written, parse_id};
use crate::error::{ApiError, ApiJson};
use crate::import::{not_found_as, validate_facts};
use crate::{AppState, transport};

/// Shares, with the `OpenAPI` description of each route taken from its
/// handler's `#[utoipa::path]`.
pub(crate) fn shares() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(offer, get_share))
        .routes(routes!(accept))
        .routes(routes!(revoke))
        .routes(routes!(list))
}

fn share_id(value: &str) -> Result<ShareId, ApiError> {
    parse_id(value, "share id")
}

/// Offers a share or changes its terms.
///
/// Changing the terms of a share that isn't revoked offers it again, so the
/// recipient must accept it again.
// r[impl authz.share.shape]
// r[impl authz.share.attributes]
#[utoipa::path(put, path = "/shares/{id}", operation_id = "offer_share", tag = "shares",
    params(("id" = ShareId, Path, description = "Chosen by the caller")),
    request_body = ShareTerms,
    responses((status = 200, body = Written<Share>)))]
async fn offer(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(terms): ApiJson<ShareTerms>,
) -> Result<Json<Written<Share>>, ApiError> {
    let id = share_id(&id)?;
    let terms = transport::share_terms(terms);
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
        value: transport::share(share),
        cursor,
    }))
}

/// Gets a share.
#[utoipa::path(get, path = "/shares/{id}", tag = "shares",
    params(("id" = ShareId, Path)),
    responses((status = 200, body = Share)))]
async fn get_share(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Share>, ApiError> {
    let id = share_id(&id)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(transport::share(
        shares::get(&mut conn, id)
            .await
            .map_err(not_found_as("share"))?,
    )))
}

/// Accepts a share.
///
/// For the recipient tenant.
// r[impl authz.share.acceptance]
#[utoipa::path(post, path = "/shares/{id}/accept", operation_id = "accept_share", tag = "shares",
    params(("id" = ShareId, Path)),
    responses((status = 200, body = Written<Share>)))]
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
        value: transport::share(share),
        cursor,
    }))
}

/// Revokes a share.
///
/// Either side can revoke it.
// r[impl authz.share.acceptance]
#[utoipa::path(post, path = "/shares/{id}/revoke", operation_id = "revoke_share", tag = "shares",
    params(("id" = ShareId, Path)),
    request_body = RevokeShare,
    responses((status = 200, body = Written<Share>)))]
async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<RevokeShare>,
) -> Result<Json<Written<Share>>, ApiError> {
    let id = share_id(&id)?;
    let mut conn = state.pool.get().await?;
    let (share, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let share = shares::revoke(conn, id, transport::store_share_side(body.by))
                .await
                .map_err(not_found_as("share"))?;
            Ok((share, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: transport::share(share),
        cursor,
    }))
}

/// Lists a tenant's shares.
#[utoipa::path(get, path = "/tenants/{id}/shares", operation_id = "list_shares", tag = "shares",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`"), ShareQuery),
    responses((status = 200, body = ShareList)))]
async fn list(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    Query(query): Query<ShareQuery>,
) -> Result<Json<ShareList>, ApiError> {
    let tenant = tenants::parse_reference(&tenant)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))?;
    let side = query.side.map(transport::store_share_side);
    let mut conn = state.pool.get().await?;
    Ok(Json(ShareList {
        shares: shares::list(&mut conn, tenant, side)
            .await?
            .into_iter()
            .map(transport::share)
            .collect(),
    }))
}
