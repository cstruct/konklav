//! Invites: an operator invites an email address, optionally into a tenant
//! with roles; the recipient redeems the delivered token with a password.

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use diesel_async::AsyncConnection;
use konklav_api::{CreateInvite, CreatedInvite};
use konklav_authn::{PasswordCheck, generate_secret, hash_challenge_secret};
use konklav_core::{CredentialId, MembershipId, SubjectId};
use konklav_store::challenges::{self, NewChallenge, Purpose};
use konklav_store::credentials::{
    self, CredentialData, CredentialKind, NewCredential, PasswordData,
};
use konklav_store::roles::{self, AssignmentTarget};
use konklav_store::subjects::{self, SubjectKind};
use konklav_store::{events, memberships, tenants};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::subject_api::start_passwordless_session;
use crate::{AppState, pacing};

/// Creating invites on the control plane, with the `OpenAPI` description
/// taken from the handler's `#[utoipa::path]`. Redeeming one is on the
/// subject-facing surface.
pub(crate) fn invites() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(create_invite))
}

pub fn subject_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/invites/redeem", post(redeem_invite))
        .route_layer(middleware::from_fn_with_state(state.clone(), pacing::pace))
}

#[derive(Serialize, Deserialize, Default)]
struct InviteDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<String>,
    #[serde(default = "empty_object")]
    facts: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    membership: Option<MembershipId>,
}

fn empty_object() -> serde_json::Value {
    serde_json::json!({})
}

/// Invites someone to a tenant.
///
/// The invite token is delivered (as `delivery.requested`) and never returned.
#[utoipa::path(post, path = "/invites", tag = "invites",
    request_body = CreateInvite,
    responses((status = 201, description = "Created; the token is delivered to the address, never returned", body = CreatedInvite)))]
async fn create_invite(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<CreateInvite>,
) -> Result<(StatusCode, Json<CreatedInvite>), ApiError> {
    if !body.email.contains('@') {
        return Err(ApiError::invalid_request("email must be an email address"));
    }
    if (!body.roles.is_empty() || body.membership.is_some()) && body.tenant.is_none() {
        return Err(ApiError::invalid_request(
            "roles and memberships need a tenant",
        ));
    }
    let mut conn = state.pool.get().await?;
    let id = uuid::Uuid::now_v7();
    let secret = generate_secret();
    let expires_at = Utc::now() + Duration::hours(body.expires_in_hours.clamp(1, 24 * 30));
    let recipient = credentials::normalize_identifier(&body.email);
    let cursor = conn
        .transaction::<_, ApiError, _>(async |conn| {
            if let Some(reference) = &body.tenant {
                let tenant = tenants::parse_reference(reference)
                    .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))?;
                tenants::get(conn, tenant)
                    .await
                    .map_err(|_| ApiError::not_found("tenant"))?;
                for role in &body.roles {
                    roles::get(conn, tenant, role)
                        .await
                        .map_err(|_| ApiError::not_found("role"))?;
                }
            }
            let details = InviteDetails {
                tenant: body.tenant.clone(),
                roles: body.roles.clone(),
                facts: body.facts.clone(),
                membership: body.membership,
            };
            challenges::create(
                conn,
                NewChallenge {
                    id,
                    purpose: Purpose::Invite,
                    subject_id: None,
                    credential_id: None,
                    mfa_factor_id: None,
                    session_id: None,
                    recipient: recipient.clone(),
                    secret_hash: hash_challenge_secret(&id.to_string(), &secret),
                    details: serde_json::to_value(&details).unwrap_or_default(),
                    expires_at,
                },
            )
            .await?;
            events::append(
                conn,
                "delivery.requested",
                serde_json::json!({
                    "channel": "email",
                    "recipient": recipient,
                    "purpose": "invite",
                    "subject": null,
                    "material": {"token": format!("{id}.{secret}")},
                    "expires_at": expires_at.timestamp(),
                }),
            )
            .await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedInvite {
            invite_id: id,
            expires_at,
            cursor,
        }),
    ))
}

#[derive(Deserialize)]
struct RedeemInvite {
    token: String,
    password: String,
}

/// The password credential already registered for `email`, if any, after
/// checking `password` against it: redeeming an invite to an existing
/// account proves ownership with that account's password.
async fn existing_account(
    state: &AppState,
    conn: &mut konklav_store::Connection,
    email: &str,
    password: &str,
) -> Result<Option<konklav_store::credentials::Credential>, ApiError> {
    let Some(existing) = credentials::find_active(conn, CredentialKind::Password, email).await?
    else {
        return Ok(None);
    };
    let CredentialData::Password(data) = &existing.data else {
        return Err(invalid_invite());
    };
    let (password, hash) = (password.to_owned(), data.hash.clone());
    let check = state
        .auth
        .hashing(move |hasher| hasher.verify(&password, &hash))
        .await?;
    if matches!(check, PasswordCheck::Match { .. }) {
        Ok(Some(existing))
    } else {
        Err(ApiError::new(
            ErrorCode::InvalidCredentials,
            "this address already has an account; use its password",
        ))
    }
}

fn invalid_invite() -> ApiError {
    ApiError::new(ErrorCode::InvalidCredentials, "invalid or expired invite")
}

/// `POST /v1/invites/redeem`: links a password credential for the invited
/// address to a new subject, or proves the existing one, then activates the
/// invited membership and starts a session.
// r[impl authn.invite.redeem]
async fn redeem_invite(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<RedeemInvite>,
) -> Result<Response, ApiError> {
    if body.password.chars().count() < 8 {
        return Err(ApiError::invalid_request(
            "passwords need at least 8 characters",
        ));
    }
    let (id, secret) = body.token.split_once('.').ok_or_else(invalid_invite)?;
    let id: uuid::Uuid = id.parse().map_err(|_| invalid_invite())?;
    let password = body.password.clone();
    let new_hash = state
        .auth
        .hashing(move |hasher| hasher.hash(&password))
        .await?;
    let mut conn = state.pool.get().await?;
    let challenge = challenges::get(&mut conn, id)
        .await
        .map_err(|_| invalid_invite())?;
    let matches: bool = hash_challenge_secret(&id.to_string(), secret)
        .ct_eq(&challenge.secret_hash)
        .into();
    if challenge.purpose != Purpose::Invite.as_str() || !challenge.is_usable(Utc::now()) || !matches
    {
        return Err(invalid_invite());
    }
    let existing =
        existing_account(&state, &mut conn, &challenge.recipient, &body.password).await?;
    let details: InviteDetails =
        serde_json::from_value(challenge.details.clone()).unwrap_or_default();
    let credential = conn
        .transaction::<_, ApiError, _>(async |conn| {
            if !challenges::consume(conn, id, Utc::now()).await? {
                return Err(invalid_invite());
            }
            let credential = match existing {
                Some(credential) => credential,
                None => {
                    let subject = SubjectId::new_v7();
                    subjects::create(conn, subject, SubjectKind::Human).await?;
                    credentials::insert(
                        conn,
                        NewCredential {
                            id: CredentialId::new_v7(),
                            subject_id: subject,
                            identifier: challenge.recipient.clone(),
                            data: CredentialData::Password(PasswordData { hash: new_hash }),
                            mfa_factors_required: 0,
                            replaces: None,
                        },
                    )
                    .await?
                }
            };
            if let Some(reference) = &details.tenant {
                let tenant = tenants::parse_reference(reference).ok_or_else(invalid_invite)?;
                // r[impl authn.invite.membership-id]
                let membership = match (
                    details.membership,
                    memberships::find_active(conn, credential.subject_id, tenant).await?,
                ) {
                    (Some(named), Some(active)) if named != active.id => {
                        return Err(ApiError::new(
                            ErrorCode::Conflict,
                            "the subject is already a member of the invited tenant",
                        ));
                    }
                    (_, Some(active)) => active,
                    (named, None) => {
                        memberships::create(
                            conn,
                            named.unwrap_or_else(MembershipId::new_v7),
                            credential.subject_id,
                            tenant,
                            &details.facts,
                        )
                        .await?
                        .0
                    }
                };
                for key in &details.roles {
                    let role = roles::get(conn, tenant, key).await?;
                    roles::assign(
                        conn,
                        role.id,
                        AssignmentTarget::Membership(membership.id),
                        None,
                    )
                    .await?;
                }
            }
            Ok(credential)
        })
        .await?;
    start_passwordless_session(&state, &mut conn, &credential, "pwd").await
}
