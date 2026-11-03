//! Registering OIDC clients on the control plane.

use axum::Json;
use axum::extract::{Path, State};
use diesel_async::AsyncConnection;
use konklav_api::{self as api, OidcClientDefinition, OidcClientSecret};
use konklav_store::credentials::{self, CredentialData, CredentialKind};
use konklav_store::oidc_clients::{self, ClientKind, IdTokenAlgorithm, OidcClient};
use konklav_store::{sessions, subjects};
use sha2::{Digest, Sha256};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{ApiError, ApiJson};
use crate::{AppState, transport};

/// OIDC clients, with the `OpenAPI` description of each route taken from
/// its handler's `#[utoipa::path]`.
pub(crate) fn oidc_clients() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(get_client, put_client, disable_client))
        .routes(routes!(new_secret))
}

/// Lists OIDC clients.
#[utoipa::path(get, path = "/oidc/clients", operation_id = "list_oidc_clients", tag = "oidc-clients",
    responses((status = 200, body = Vec<api::OidcClient>)))]
async fn list(State(state): State<AppState>) -> Result<Json<Vec<api::OidcClient>>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(
        oidc_clients::list(&mut conn)
            .await?
            .into_iter()
            .map(transport::oidc_client)
            .collect(),
    ))
}

/// Gets an OIDC client.
#[utoipa::path(get, path = "/oidc/clients/{id}", operation_id = "get_oidc_client", tag = "oidc-clients",
    params(("id" = String, Path, description = "The client id")),
    responses((status = 200, body = api::OidcClient)))]
async fn get_client(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<api::OidcClient>, ApiError> {
    let mut conn = state.pool.get().await?;
    oidc_clients::get(&mut conn, &id)
        .await
        .map(|client| Json(transport::oidc_client(client)))
        .map_err(|_| ApiError::not_found("OIDC client"))
}

/// Registers or replaces an OIDC client.
///
/// A disabled client is enabled again.
#[utoipa::path(put, path = "/oidc/clients/{id}", operation_id = "put_oidc_client", tag = "oidc-clients",
    params(("id" = String, Path, description = "The client id, chosen by the caller")),
    request_body = OidcClientDefinition,
    responses((status = 200, body = api::OidcClient)))]
async fn put_client(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(definition): ApiJson<OidcClientDefinition>,
) -> Result<Json<api::OidcClient>, ApiError> {
    let definition = transport::client_definition(definition);
    if !definition.scopes.iter().any(|s| s == "openid") {
        return Err(ApiError::invalid_request("clients need the openid scope"));
    }
    // A client's tokens would otherwise pass as Konklav's own, on the
    // subject-facing and control-plane surfaces.
    // r[impl oidc.provider.client-audience]
    if definition.audience == state.auth.audience {
        return Err(ApiError::invalid_request(
            "a client's audience can't be Konklav's own",
        ));
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
    if let Some(jwks) = &definition.jwks
        && serde_json::from_value::<jsonwebtoken::jwk::JwkSet>(jwks.clone()).is_err()
    {
        return Err(ApiError::invalid_request("jwks must be a JWK set"));
    }
    // r[impl oidc.provider.algorithms]
    let has_rsa = state
        .auth
        .oidc
        .as_ref()
        .is_some_and(|provider| provider.algorithms().contains(&"RS256"));
    if definition.id_token_alg == IdTokenAlgorithm::Rs256 && !has_rsa {
        return Err(ApiError::invalid_request(
            "RS256 ID tokens need an RSA key (oidc_provider.rsa_key_file)",
        ));
    }
    // PKCE is all that protects a public client's codes.
    // r[impl oidc.provider.code-flow]
    if !definition.require_pkce && definition.kind != ClientKind::Confidential {
        return Err(ApiError::invalid_request(
            "only confidential clients can be registered without PKCE",
        ));
    }
    if definition.service_subject.is_some() && definition.kind != ClientKind::Confidential {
        return Err(ApiError::invalid_request(
            "only confidential clients can act as service principals",
        ));
    }
    let mut conn = state.pool.get().await?;
    conn.transaction::<_, ApiError, _>(async |conn| {
        let client = oidc_clients::put(conn, &id, &definition).await?;
        bind_service_subject(conn, &client).await?;
        Ok(Json(transport::oidc_client(client)))
    })
    .await
}

/// Keeps the client's `client` credential on its service principal, if it
/// has one: creates it, moves it when the principal changes, and revokes it
/// (and its sessions) when the binding is removed.
// r[impl oidc.provider.client-credentials]
async fn bind_service_subject(
    conn: &mut konklav_store::Connection,
    client: &OidcClient,
) -> Result<(), ApiError> {
    let current = credentials::find_active(conn, CredentialKind::Client, &client.id).await?;
    if let Some(credential) = &current
        && Some(credential.subject_id) != client.service_subject
    {
        credentials::revoke(conn, credential.id, "client_rebound").await?;
        let filter = sessions::SessionFilter {
            credential: Some(credential.id),
            ..Default::default()
        };
        sessions::revoke(conn, &filter, None, "credential_revoked").await?;
    }
    let Some(subject) = client.service_subject else {
        return Ok(());
    };
    if current.is_some_and(|c| c.subject_id == subject) {
        return Ok(());
    }
    let principal = subjects::get(conn, subject)
        .await
        .map_err(|_| ApiError::not_found("service subject"))?;
    if principal.kind != subjects::SubjectKind::Service {
        return Err(ApiError::invalid_request(
            "service_subject must be a service principal",
        ));
    }
    credentials::insert(
        conn,
        credentials::NewCredential {
            id: konklav_core::CredentialId::new_v7(),
            subject_id: subject,
            identifier: client.id.clone(),
            data: CredentialData::Client,
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await?;
    Ok(())
}

/// Disables an OIDC client.
///
/// The client's sessions are revoked. The registration stays, as history.
#[utoipa::path(delete, path = "/oidc/clients/{id}", operation_id = "disable_oidc_client", tag = "oidc-clients",
    params(("id" = String, Path, description = "The client id")),
    responses((status = 200, description = "Disabled; the registration stays", body = api::OidcClient)))]
async fn disable_client(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<api::OidcClient>, ApiError> {
    let mut conn = state.pool.get().await?;
    conn.transaction::<_, ApiError, _>(async |conn| {
        oidc_clients::get(conn, &id)
            .await
            .map_err(|_| ApiError::not_found("OIDC client"))?;
        oidc_clients::disable(conn, &id).await?;
        sessions::revoke_for_client(conn, &id, "client_disabled").await?;
        Ok(Json(transport::oidc_client(
            oidc_clients::get(conn, &id).await?,
        )))
    })
    .await
}

/// Issues a new OIDC client secret.
///
/// Only for confidential clients. The secret is shown only once, and the
/// previous one stops working.
#[utoipa::path(post, path = "/oidc/clients/{id}/secret", operation_id = "new_oidc_client_secret", tag = "oidc-clients",
    params(("id" = String, Path, description = "The client id")),
    responses((status = 200, description = "The new secret, shown only once", body = OidcClientSecret)))]
async fn new_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<OidcClientSecret>, ApiError> {
    let mut conn = state.pool.get().await?;
    let client = oidc_clients::get(&mut conn, &id)
        .await
        .map_err(|_| ApiError::not_found("OIDC client"))?;
    if client.kind != ClientKind::Confidential {
        return Err(ApiError::invalid_request("public clients have no secret"));
    }
    let secret = konklav_authn::generate_secret();
    oidc_clients::set_secret_hash(&mut conn, &id, &Sha256::digest(secret.as_bytes())).await?;
    Ok(Json(OidcClientSecret {
        client_secret: secret,
    }))
}
