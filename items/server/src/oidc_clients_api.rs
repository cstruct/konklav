//! Registering OIDC clients on the control plane.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use conclave_store::oidc_clients::{self, ClientDefinition, ClientKind, OidcClient};
use conclave_store::sessions;
use diesel_async::AsyncConnection;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::control_api::guard;
use crate::error::{ApiError, ApiJson};
use crate::{AppState, capabilities};

pub fn routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/oidc/clients", get(list))
        .route(
            "/oidc/clients/{id}",
            get(get_client).put(put_client).delete(disable_client),
        )
        .route("/oidc/clients/{id}/secret", post(new_secret))
        .route_layer(guard(state, capabilities::CLIENTS))
}

async fn list(State(state): State<AppState>) -> Result<Json<Vec<OidcClient>>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(oidc_clients::list(&mut conn).await?))
}

async fn get_client(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<OidcClient>, ApiError> {
    let mut conn = state.pool.get().await?;
    oidc_clients::get(&mut conn, &id)
        .await
        .map(Json)
        .map_err(|_| ApiError::not_found("OIDC client"))
}

/// `PUT /v1/oidc/clients/{id}`: registers or replaces a client, enabling it
/// again if it was disabled.
async fn put_client(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(definition): ApiJson<ClientDefinition>,
) -> Result<Json<OidcClient>, ApiError> {
    if !definition.scopes.iter().any(|s| s == "openid") {
        return Err(ApiError::invalid_request("clients need the openid scope"));
    }
    for uri in &definition.redirect_uris {
        let parsed = reqwest::Url::parse(uri)
            .map_err(|_| ApiError::invalid_request(format!("`{uri}` is not a URL")))?;
        if parsed.fragment().is_some() {
            return Err(ApiError::invalid_request(
                "redirect URIs can't have fragments",
            ));
        }
    }
    let mut conn = state.pool.get().await?;
    Ok(Json(oidc_clients::put(&mut conn, &id, &definition).await?))
}

/// `DELETE /v1/oidc/clients/{id}`: disables the client and revokes its
/// sessions. The registration stays, as history.
async fn disable_client(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<OidcClient>, ApiError> {
    let mut conn = state.pool.get().await?;
    conn.transaction::<_, ApiError, _>(async |conn| {
        oidc_clients::get(conn, &id)
            .await
            .map_err(|_| ApiError::not_found("OIDC client"))?;
        oidc_clients::disable(conn, &id).await?;
        sessions::revoke_for_client(conn, &id, "client_disabled").await?;
        Ok(Json(oidc_clients::get(conn, &id).await?))
    })
    .await
}

#[derive(Serialize)]
struct NewSecret {
    client_secret: String,
}

/// `POST /v1/oidc/clients/{id}/secret`: a new secret for a confidential
/// client, shown only once. The previous secret stops working.
async fn new_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<NewSecret>, ApiError> {
    let mut conn = state.pool.get().await?;
    let client = oidc_clients::get(&mut conn, &id)
        .await
        .map_err(|_| ApiError::not_found("OIDC client"))?;
    if client.kind != ClientKind::Confidential {
        return Err(ApiError::invalid_request("public clients have no secret"));
    }
    let secret = conclave_authn::generate_secret();
    oidc_clients::set_secret_hash(&mut conn, &id, &Sha256::digest(secret.as_bytes())).await?;
    Ok(Json(NewSecret {
        client_secret: secret,
    }))
}
