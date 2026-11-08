//! Invites: an operator invites someone, optionally into a tenant with
//! roles. An emailed invite's token is delivered to the address, whose owner
//! redeems it with a password. A link-only invite's token is shown once, for
//! the relying system to share; whoever holds it redeems it, signed in or
//! with an existing account's password. Anyone holding a token may preview
//! the invite first.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use diesel_async::AsyncConnection;
use konklav_api::{
    CreateInvite, CreatedInvite, Invite, InvitePage, InvitePreview, InviteQuery, InviteState,
    PreviewState,
};

use crate::client_address::ClientAddress;
use crate::control_api::{Written, created_status};
use crate::db::Db;
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
use crate::subject_api::{
    Client, SessionRequest, begin_token_attempt, check_password, start_passwordless_session,
    start_session,
};
use crate::{AppState, metadata, pacing};

/// Creating invites on the control plane, with the `OpenAPI` description
/// taken from the handler's `#[utoipa::path]`. Redeeming one is on the
/// subject-facing surface.
pub(crate) fn invites() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create_invite, list_invites))
        .routes(routes!(get_invite))
        .routes(routes!(revoke_invite))
}

pub fn subject_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/invites/redeem", post(redeem_invite))
        .route("/invites/preview", post(preview_invite))
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
    /// Left out when empty, so invites created before it existed compare
    /// equal on an idempotent repeat.
    #[serde(default = "empty_object", skip_serializing_if = "is_empty_object")]
    public_metadata: serde_json::Value,
}

fn empty_object() -> serde_json::Value {
    serde_json::json!({})
}

fn is_empty_object(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

/// The size limit of an invite's public metadata, in bytes of compact JSON.
const PUBLIC_METADATA_LIMIT: usize = 1024;

/// A link-only invite has no recipient.
fn is_link_only(invite: &challenges::Challenge) -> bool {
    invite.recipient.is_empty()
}

fn token_of(invite: uuid::Uuid, secret: &str) -> String {
    format!("{invite}.{secret}")
}

/// Invites someone, optionally to a tenant.
///
/// With an `email`, the invite token is delivered (as `delivery.requested`)
/// and never returned. Without one, the invite is link-only: nothing is
/// delivered, and `token` shows the token once, for the relying system to
/// share as a link that whoever holds it may redeem.
/// Idempotent on a caller-chosen `id`: repeating the request with the same
/// content returns 200 and delivers nothing again; for a pending link-only
/// invite it shows a new token and stops accepting the first.
#[utoipa::path(post, path = "/invites", tag = "invites",
    request_body = CreateInvite,
    responses(
        (status = 201, description = "Created. An emailed invite's token is delivered to the address, never returned; a link-only invite's is in `token`, shown only once.", body = Written<CreatedInvite>),
        (status = 200, description = "Already existed with the same content; nothing is delivered again. A pending link-only invite's new token is in `token`.", body = Written<CreatedInvite>),
    ))]
// r[impl metadata.write.create]
// r[impl metadata.invites]
// r[impl authn.invite.emailed]
// r[impl authn.invite.link-only]
async fn create_invite(
    db: Db,
    limit: metadata::Limit,
    ApiJson(body): ApiJson<CreateInvite>,
) -> Result<(StatusCode, Json<Written<CreatedInvite>>), ApiError> {
    limit.check(&body.metadata)?;
    // r[impl metadata.public]
    check_public_metadata(&body.public_metadata)?;
    if body
        .email
        .as_ref()
        .is_some_and(|email| !email.contains('@'))
    {
        return Err(ApiError::invalid_request("email must be an email address"));
    }
    if (!body.roles.is_empty() || body.membership.is_some()) && body.tenant.is_none() {
        return Err(ApiError::invalid_request(
            "roles and memberships need a tenant",
        ));
    }
    let mut conn = db.get().await?;
    let id = body.id.unwrap_or_else(uuid::Uuid::now_v7);
    let secret = generate_secret();
    let expires_at = Utc::now() + Duration::hours(body.expires_in_hours.clamp(1, 24 * 30));
    // A link-only invite has no recipient.
    let recipient = body
        .email
        .as_deref()
        .map(credentials::normalize_identifier)
        .unwrap_or_default();
    let details = serde_json::to_value(InviteDetails {
        tenant: body.tenant.clone(),
        roles: body.roles.clone(),
        facts: body.facts.clone(),
        membership: body.membership,
        public_metadata: body.public_metadata.clone(),
    })
    .unwrap_or_default();
    let (expires_at, created, token, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            // r[impl platform.idempotency.client-ids]
            if body.id.is_some()
                && let Ok(existing) = challenges::get(conn, id).await
            {
                return repeat(
                    conn,
                    &existing,
                    (&recipient, &details, &body.metadata),
                    &secret,
                )
                .await;
            }
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
            // What Postgres stored, to the microsecond, so a repeat answers
            // the same `expires_at`.
            let created = challenges::create_with_metadata(
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
                    details: details.clone(),
                    expires_at,
                },
                &body.metadata,
            )
            .await?;
            let token = if is_link_only(&created) {
                Some(token_of(id, &secret))
            } else {
                request_delivery(conn, &created, &secret).await?;
                None
            };
            Ok((
                created.expires_at,
                true,
                token,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok((
        created_status(created),
        Json(Written {
            value: CreatedInvite {
                invite_id: id,
                expires_at,
                token,
            },
            cursor,
        }),
    ))
}

/// Answers an idempotent repeat of a create: the same invite again, with a
/// new token for a pending link-only invite, since Konklav keeps only the
/// token's hash; or a conflict when the content differs.
// r[impl authn.invite.link-only]
async fn repeat(
    conn: &mut konklav_store::Connection,
    existing: &challenges::Challenge,
    (recipient, details, metadata): (&str, &serde_json::Value, &serde_json::Value),
    secret: &str,
) -> Result<
    (
        chrono::DateTime<Utc>,
        bool,
        Option<String>,
        Option<konklav_core::Cursor>,
    ),
    ApiError,
> {
    let id = existing.id;
    let same = existing.purpose == Purpose::Invite.as_str()
        && existing.recipient == recipient
        && existing.details == *details
        && existing.metadata == *metadata;
    if !same {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            format!("invite {id} already exists with other content"),
        ));
    }
    let shown = is_link_only(existing)
        && challenges::replace_secret(
            conn,
            id,
            &hash_challenge_secret(&id.to_string(), secret),
            Utc::now(),
        )
        .await?;
    Ok((
        existing.expires_at,
        false,
        shown.then(|| token_of(id, secret)),
        None,
    ))
}

/// Checks that `public_metadata` is an object within its small limit.
// r[impl metadata.public]
fn check_public_metadata(public_metadata: &serde_json::Value) -> Result<(), ApiError> {
    if !public_metadata.is_object() {
        return Err(ApiError::invalid_request(
            "public_metadata must be a JSON object",
        ));
    }
    let size = serde_json::to_vec(public_metadata).map_or(usize::MAX, |bytes| bytes.len());
    if size > PUBLIC_METADATA_LIMIT {
        return Err(ApiError::new(
            ErrorCode::MetadataTooLarge,
            format!(
                "public_metadata takes {size} bytes, more than the {PUBLIC_METADATA_LIMIT} allowed"
            ),
        ));
    }
    Ok(())
}

/// Asks for the invite's token to be delivered, with the invite's id and
/// metadata so the deliverer can write the message.
// r[impl metadata.invites]
async fn request_delivery(
    conn: &mut konklav_store::Connection,
    invite: &challenges::Challenge,
    secret: &str,
) -> Result<(), ApiError> {
    events::append(
        conn,
        "delivery.requested",
        serde_json::json!({
            "channel": "email",
            "recipient": invite.recipient,
            "purpose": "invite",
            "subject": null,
            "material": {"token": token_of(invite.id, secret)},
            "expires_at": invite.expires_at.timestamp(),
            "invite": invite.id,
            "metadata": invite.metadata,
        }),
    )
    .await?;
    Ok(())
}

/// Lists invites, newest first.
///
/// Optionally only those to one tenant, or whose metadata matches a filter.
// r[impl metadata.invites]
// r[impl metadata.filter]
#[utoipa::path(get, path = "/invites", tag = "invites", params(InviteQuery),
    responses((status = 200, body = InvitePage)))]
async fn list_invites(
    db: Db,
    Query(query): Query<InviteQuery>,
) -> Result<Json<InvitePage>, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let tenant = query
        .tenant
        .as_deref()
        .map(|reference| {
            tenants::parse_reference(reference)
                .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))
        })
        .transpose()?;
    let filter = metadata::filter(query.metadata.as_deref())?;
    let mut conn = db.get().await?;
    let found =
        challenges::list_invites(&mut conn, tenant, filter.as_ref(), query.before, limit).await?;
    let next = (i64::try_from(found.len()) == Ok(limit))
        .then(|| found.last().map(|invite| invite.id))
        .flatten();
    Ok(Json(InvitePage {
        invites: found.into_iter().map(invite).collect(),
        next,
    }))
}

/// Gets an invite, without its token.
#[utoipa::path(get, path = "/invites/{id}", tag = "invites", params(("id" = uuid::Uuid, Path)),
    responses((status = 200, body = Invite)))]
async fn get_invite(db: Db, Path(id): Path<String>) -> Result<Json<Invite>, ApiError> {
    let id = parse_invite_id(&id)?;
    let mut conn = db.get().await?;
    Ok(Json(invite(find_invite(&mut conn, id).await?)))
}

/// Revokes an invite, so it can no longer be redeemed.
///
/// Redeeming a revoked invite fails as redeeming an expired one does.
/// Revoking it again answers the same; a redeemed invite can't be revoked.
// r[impl authn.invite.revoke]
#[utoipa::path(post, path = "/invites/{id}/revoke", tag = "invites", params(("id" = uuid::Uuid, Path)),
    responses(
        (status = 200, body = Invite),
        (status = 409, description = "Already redeemed", body = konklav_api::ErrorResponse),
    ))]
async fn revoke_invite(db: Db, Path(id): Path<String>) -> Result<Json<Invite>, ApiError> {
    let id = parse_invite_id(&id)?;
    let mut conn = db.get().await?;
    find_invite(&mut conn, id).await?;
    challenges::revoke(&mut conn, id, Utc::now()).await?;
    let revoked = find_invite(&mut conn, id).await?;
    if revoked.revoked_at.is_none() {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "the invite was already redeemed",
        ));
    }
    Ok(Json(invite(revoked)))
}

fn parse_invite_id(id: &str) -> Result<uuid::Uuid, ApiError> {
    id.parse()
        .map_err(|_| ApiError::invalid_request("invite id must be a UUID"))
}

async fn find_invite(
    conn: &mut konklav_store::Connection,
    id: uuid::Uuid,
) -> Result<challenges::Challenge, ApiError> {
    match challenges::get(conn, id).await {
        Ok(challenge) if challenge.purpose == Purpose::Invite.as_str() => Ok(challenge),
        _ => Err(ApiError::not_found("invite")),
    }
}

pub(crate) fn invite(challenge: challenges::Challenge) -> Invite {
    let state = if challenge.revoked_at.is_some() {
        InviteState::Revoked
    } else if challenge.consumed_at.is_some() {
        InviteState::Redeemed
    } else if challenge.is_usable(Utc::now()) {
        InviteState::Pending
    } else {
        InviteState::Expired
    };
    let details: InviteDetails = serde_json::from_value(challenge.details).unwrap_or_default();
    let link_only = challenge.recipient.is_empty();
    Invite {
        id: challenge.id,
        email: (!link_only).then_some(challenge.recipient),
        tenant: details.tenant,
        roles: details.roles,
        membership: details.membership,
        state,
        expires_at: challenge.expires_at,
        consumed_at: challenge.consumed_at,
        metadata_etag: metadata::etag(&challenge.metadata),
        metadata: challenge.metadata,
        public_metadata: details.public_metadata,
    }
}

#[derive(Deserialize)]
struct RedeemInvite {
    token: String,
    /// A new password for an emailed invite's address, or that address's
    /// existing one; or, with `identifier`, a link-only invite redeemer's.
    #[serde(default)]
    password: Option<String>,
    /// For a link-only invite redeemed without a session: the login
    /// identifier of the existing password credential `password` proves.
    #[serde(default)]
    identifier: Option<String>,
    #[serde(flatten)]
    session: SessionRequest,
}

#[derive(Deserialize)]
struct PreviewRequest {
    token: String,
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

/// Finds the invite `token` names and proves its secret, counting the check
/// against the client's address. An unknown token, a malformed one and one
/// with the wrong secret fail alike. The invite may no longer be usable.
// r[impl authn.invite.token-limits]
async fn check_token(
    conn: &mut konklav_store::Connection,
    token: &str,
    address: ClientAddress,
) -> Result<challenges::Challenge, ApiError> {
    let parsed = token
        .split_once('.')
        .and_then(|(id, secret)| Some((id.parse::<uuid::Uuid>().ok()?, secret)));
    let attempt = begin_token_attempt(
        conn,
        parsed.map_or(uuid::Uuid::nil(), |(id, _)| id),
        address,
    )
    .await?;
    let mut found = None;
    if let Some((id, secret)) = parsed
        && let Ok(challenge) = challenges::get(conn, id).await
    {
        let matches: bool = hash_challenge_secret(&id.to_string(), secret)
            .ct_eq(&challenge.secret_hash)
            .into();
        if matches && challenge.purpose == Purpose::Invite.as_str() {
            found = Some(challenge);
        }
    }
    attempt.finish(conn, found.is_some()).await?;
    found.ok_or_else(invalid_invite)
}

/// `POST /v1/invites/preview`: what an invite is for, shown to whoever
/// holds its token before signing in, so a login application can say who
/// invites them to what. Invites that can't be redeemed fail as redeeming
/// them would, so a revoked invite looks expired, or unknown.
// r[impl authn.invite.preview]
// r[impl metadata.public]
async fn preview_invite(
    State(state): State<AppState>,
    address: ClientAddress,
    ApiJson(body): ApiJson<PreviewRequest>,
) -> Result<Json<InvitePreview>, ApiError> {
    let mut conn = state.pool.get().await?;
    let challenge = check_token(&mut conn, &body.token, address).await?;
    let state = match invite(challenge.clone()).state {
        InviteState::Pending => PreviewState::Pending,
        InviteState::Redeemed => PreviewState::Redeemed,
        InviteState::Revoked | InviteState::Expired => return Err(invalid_invite()),
    };
    let details: InviteDetails = serde_json::from_value(challenge.details).unwrap_or_default();
    Ok(Json(InvitePreview {
        state,
        expires_at: challenge.expires_at,
        link_only: challenge.recipient.is_empty(),
        public_metadata: details.public_metadata,
    }))
}

/// `POST /v1/invites/redeem`. An emailed invite links a password credential
/// for the invited address to a new subject, or proves the existing one. A
/// link-only invite is redeemed by whoever holds it: a signed-in subject
/// (with an `Authorization` header), or the owner of an existing password
/// account. Either way the invited membership is activated, and a login
/// starts a session.
// r[impl authn.invite.redeem]
// r[impl authn.login.session-request]
async fn redeem_invite(
    State(state): State<AppState>,
    crate::dpop::Bound(dpop_jkt): crate::dpop::Bound,
    address: ClientAddress,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RedeemInvite>,
) -> Result<Response, ApiError> {
    if headers.contains_key(header::AUTHORIZATION) {
        return redeem_signed_in(&state, address, &headers, body).await;
    }
    let password = body
        .password
        .clone()
        .ok_or_else(|| ApiError::invalid_request("a password is required without a session"))?;
    if body.identifier.is_none() && password.chars().count() < 8 {
        return Err(ApiError::invalid_request(
            "passwords need at least 8 characters",
        ));
    }
    let mut conn = state.pool.get().await?;
    let browser = body.session.check(&state, &mut conn, &headers).await?;
    let challenge = usable(check_token(&mut conn, &body.token, address).await?)?;
    let credential = if is_link_only(&challenge) {
        // r[impl authn.invite.bearer]
        let identifier = body.identifier.as_deref().ok_or_else(|| {
            ApiError::invalid_request(
                "a link-only invite is redeemed signed in, or with the identifier and \
                 password of an existing account",
            )
        })?;
        Some(check_password(&state, &mut conn, identifier, password.clone(), address).await?)
    } else if body.identifier.is_some() {
        return Err(ApiError::invalid_request(
            "an invite to an address is redeemed with its password alone",
        ));
    } else {
        None
    };
    if let Some(credential) = credential {
        consume_and_join(&mut conn, &challenge, credential.subject_id).await?;
        // The account signs in as password login would, MFA and all.
        return start_session(
            &state,
            &mut conn,
            &credential,
            &["pwd"],
            body.session.client,
            browser.as_ref(),
            &body.session.flags,
            dpop_jkt,
        )
        .await;
    }
    let credential = redeem_emailed(&state, &mut conn, &challenge, &password).await?;
    start_passwordless_session(
        &state,
        &mut conn,
        &credential,
        "pwd",
        &body.session,
        browser.as_ref(),
        dpop_jkt,
    )
    .await
}

/// `challenge` if it can still be redeemed.
fn usable(challenge: challenges::Challenge) -> Result<challenges::Challenge, ApiError> {
    if challenge.is_usable(Utc::now()) {
        Ok(challenge)
    } else {
        Err(invalid_invite())
    }
}

/// Redeems an emailed invite with `password`: links a password credential
/// for the address to a new subject, or proves the existing account's.
async fn redeem_emailed(
    state: &AppState,
    conn: &mut konklav_store::Connection,
    challenge: &challenges::Challenge,
    password: &str,
) -> Result<konklav_store::credentials::Credential, ApiError> {
    let new = password.to_owned();
    let new_hash = state.auth.hashing(move |hasher| hasher.hash(&new)).await?;
    let existing = existing_account(state, conn, &challenge.recipient, password).await?;
    conn.transaction::<_, ApiError, _>(async |conn| {
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
                        metadata: konklav_store::metadata::empty(),
                    },
                )
                .await?
            }
        };
        consume_and_join(conn, challenge, credential.subject_id).await?;
        Ok(credential)
    })
    .await
}

/// What a signed-in redemption answers: the membership it joined, if any,
/// and the change-feed cursor of its last event.
#[derive(Serialize)]
struct Redeemed {
    invite: uuid::Uuid,
    subject: SubjectId,
    tenant: Option<konklav_core::TenantId>,
    membership: Option<MembershipId>,
    cursor: Option<konklav_core::Cursor>,
}

/// Redeems a link-only invite for the signed-in subject. It starts no
/// session and leaves the caller's alone: restrictive flags can only be
/// asked for when signing in.
// r[impl authn.invite.bearer]
async fn redeem_signed_in(
    state: &AppState,
    address: ClientAddress,
    headers: &HeaderMap,
    body: RedeemInvite,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let session = crate::flows::own_session(state, &mut conn, headers).await?;
    if body.password.is_some()
        || body.identifier.is_some()
        || !body.session.flags.is_empty()
        || matches!(body.session.client, Client::Browser)
    {
        return Err(ApiError::invalid_request(
            "a signed-in redemption takes only the token: it starts no session",
        ));
    }
    let subject = subjects::get(&mut conn, session.subject_id).await?;
    if subject.state != konklav_store::subjects::SubjectState::Active
        || subject.kind != SubjectKind::Human
    {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "only people can redeem invites",
        ));
    }
    let challenge = usable(check_token(&mut conn, &body.token, address).await?)?;
    if !is_link_only(&challenge) {
        return Err(ApiError::invalid_request(
            "an invite to an address is redeemed with its password, not signed in",
        ));
    }
    let (membership, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let membership = consume_and_join(conn, &challenge, session.subject_id).await?;
            Ok((membership, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Redeemed {
        invite: challenge.id,
        subject: session.subject_id,
        tenant: membership.as_ref().map(|m| m.tenant_id),
        membership: membership.as_ref().map(|m| m.id),
        cursor,
    })
    .into_response())
}

/// Consumes the invite, so it is redeemed at most once, joins its tenant
/// and emits `invite.redeemed`, all in one transaction.
// r[impl metadata.invites]
// r[impl authn.invite.redeemed-event]
async fn consume_and_join(
    conn: &mut konklav_store::Connection,
    challenge: &challenges::Challenge,
    subject: SubjectId,
) -> Result<Option<memberships::Membership>, ApiError> {
    conn.transaction::<_, ApiError, _>(async |conn| {
        if !challenges::consume(conn, challenge.id, Utc::now()).await? {
            return Err(invalid_invite());
        }
        let details: InviteDetails =
            serde_json::from_value(challenge.details.clone()).unwrap_or_default();
        let membership = join_invited_tenant(conn, &details, subject).await?;
        events::append(
            conn,
            "invite.redeemed",
            serde_json::json!({
                "invite": challenge.id,
                "subject": subject,
                "tenant": membership.as_ref().map(|m| m.tenant_id),
                "membership": membership.as_ref().map(|m| m.id),
                "metadata": challenge.metadata,
            }),
        )
        .await?;
        Ok(membership)
    })
    .await
}

/// Activates the membership an invite targets, if any, with its roles, and
/// returns it.
async fn join_invited_tenant(
    conn: &mut konklav_store::Connection,
    details: &InviteDetails,
    subject: SubjectId,
) -> Result<Option<memberships::Membership>, ApiError> {
    let Some(reference) = &details.tenant else {
        return Ok(None);
    };
    let tenant = tenants::parse_reference(reference).ok_or_else(invalid_invite)?;
    // r[impl authn.invite.membership-id]
    let membership = match (
        details.membership,
        memberships::find_active(conn, subject, tenant).await?,
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
                subject,
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
    Ok(Some(membership))
}
