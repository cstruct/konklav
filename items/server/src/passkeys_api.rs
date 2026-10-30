//! The subject-facing passkey surface: registering, logging in, stepping
//! up, and listing and removing a subject's own passkeys.
//!
//! Every ceremony has two calls. The first stores the `webauthn-rs` state in
//! a challenge and returns the browser's options with a `ceremony` token
//! naming that challenge; the second brings the token back with the
//! browser's response.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use diesel_async::AsyncConnection;
use konklav_authn::{generate_secret, hash_challenge_secret};
use konklav_core::{CredentialId, Cursor, SubjectId};
use konklav_store::Connection;
use konklav_store::challenges::{self, Challenge, NewChallenge, Purpose};
use konklav_store::credentials::{
    self, Credential, CredentialData, CredentialKind, NewCredential, PublicKeyData,
};
use konklav_store::sessions::{self, Session, SessionFilter, Stage};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::passkeys::{Rejected, Verifier};
use crate::subject_api::{
    Client, authenticate, begin_attempt, check_browser_request, check_requested_flags,
    invalid_credentials, refuse_impersonation, start_session,
};
use crate::{AppState, pacing};

pub fn routes(state: &AppState) -> Router<AppState> {
    let paced = Router::new()
        .route("/login/passkey/options", post(login_options))
        .route("/login/passkey", post(login))
        .route("/step-up/passkey/options", post(step_up_options))
        .route_layer(middleware::from_fn_with_state(state.clone(), pacing::pace));
    Router::new()
        .merge(paced)
        .route("/passkeys", get(list))
        .route("/passkeys/registration/options", post(registration_options))
        .route("/passkeys/registration", post(register))
        .route("/passkeys/{id}", delete(remove))
}

/// Methods a passkey login or step-up records: possession of a software
/// key plus user verification.
// r[impl authn.passkey.amr]
pub(crate) const PASSKEY_AMR: [&str; 2] = ["swk", "mfa"];

/// How long a ceremony may take; WebAuthn's recommended timeout.
const CEREMONY_MINUTES: i64 = 5;
/// Registering or removing a passkey needs an authentication this recent.
const RECENT_AUTH_MINUTES: i64 = 10;
/// Registrations a subject may start per 10 minutes.
const REGISTRATION_LIMIT: i64 = 10;
const LABEL_MAX: usize = 100;

fn verifier(state: &AppState) -> Result<&Verifier, ApiError> {
    state
        .auth
        .passkeys
        .as_ref()
        .ok_or_else(|| ApiError::not_found("passkeys"))
}

fn rejected(error: &Rejected) -> ApiError {
    tracing::debug!(%error, "passkey rejected");
    invalid_credentials()
}

/// The browser's options and the token naming the ceremony.
#[derive(Serialize)]
struct Ceremony<T> {
    ceremony: String,
    options: T,
}

/// A passkey as its subject sees it.
#[derive(Serialize)]
struct PasskeyView {
    id: CredentialId,
    label: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl PasskeyView {
    fn of(credential: &Credential) -> Option<Self> {
        let CredentialData::PublicKey(data) = &credential.data else {
            return None;
        };
        Some(Self {
            id: credential.id,
            label: data.label.clone(),
            created_at: credential.created_at,
            last_used_at: data.last_used_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Details {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    state: serde_json::Value,
}

/// Stores ceremony state and returns its `<id>.<secret>` token.
// r[impl challenge.single-use]
async fn begin(
    conn: &mut Connection,
    purpose: Purpose,
    subject: Option<SubjectId>,
    session: Option<&Session>,
    details: Details,
) -> Result<String, ApiError> {
    let id = uuid::Uuid::now_v7();
    let secret = generate_secret();
    challenges::create(
        conn,
        NewChallenge {
            id,
            purpose,
            subject_id: subject,
            credential_id: None,
            mfa_factor_id: None,
            session_id: session.map(|s| s.id),
            recipient: subject.map(|s| s.to_string()).unwrap_or_default(),
            secret_hash: hash_challenge_secret(&id.to_string(), &secret),
            details: serde_json::to_value(&details).map_err(ApiError::internal)?,
            expires_at: Utc::now() + Duration::minutes(CEREMONY_MINUTES),
        },
    )
    .await?;
    Ok(format!("{id}.{secret}"))
}

/// Finds and consumes the ceremony `token` names. It must have `purpose`
/// and belong to `session` (or to none). Consumed even if what follows
/// fails, so every ceremony is tried at most once.
async fn take(
    conn: &mut Connection,
    token: &str,
    purpose: Purpose,
    session: Option<&Session>,
) -> Result<Details, ApiError> {
    let (id, secret) = token.split_once('.').ok_or_else(invalid_credentials)?;
    let id: uuid::Uuid = id.parse().map_err(|_| invalid_credentials())?;
    let challenge: Challenge = challenges::get(conn, id)
        .await
        .map_err(|_| invalid_credentials())?;
    let matches: bool = hash_challenge_secret(&id.to_string(), secret)
        .ct_eq(&challenge.secret_hash)
        .into();
    if !matches
        || challenge.purpose != purpose.as_str()
        || challenge.session_id != session.map(|s| s.id)
        || !challenge.is_usable(Utc::now())
        || !challenges::consume(conn, id, Utc::now()).await?
    {
        return Err(invalid_credentials());
    }
    serde_json::from_value(challenge.details).map_err(|_| invalid_credentials())
}

/// A full session of a human subject.
async fn full_session(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
) -> Result<Session, ApiError> {
    let (_, session) = authenticate(state, conn, headers).await?;
    if session.stage == Stage::Partial {
        return Err(ApiError::new(ErrorCode::Forbidden, "complete MFA first"));
    }
    let subject = subjects::get(conn, session.subject_id).await?;
    if subject.kind != SubjectKind::Human {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "only people can have passkeys",
        ));
    }
    Ok(session)
}

/// A full session that authenticated within [`RECENT_AUTH_MINUTES`].
async fn recent_session(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
) -> Result<Session, ApiError> {
    let session = full_session(state, conn, headers).await?;
    refuse_impersonation(&session)?;
    if Utc::now() - session.auth_time > Duration::minutes(RECENT_AUTH_MINUTES) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "authenticate again (step up) first",
        ));
    }
    Ok(session)
}

/// The subject's active passkeys.
async fn passkeys_of(
    conn: &mut Connection,
    subject: SubjectId,
) -> Result<Vec<Credential>, ApiError> {
    Ok(credentials::list_for_subject(conn, subject)
        .await?
        .into_iter()
        .filter(|c| c.is_active() && c.kind() == CredentialKind::PublicKey)
        .collect())
}

fn key_data(credential: &Credential) -> Option<&PublicKeyData> {
    match &credential.data {
        CredentialData::PublicKey(data) => Some(data),
        _ => None,
    }
}

/// The name a passkey manager shows for the account: a login identifier
/// the subject knows, or its id.
async fn account_name(conn: &mut Connection, subject: SubjectId) -> Result<String, ApiError> {
    Ok(credentials::list_for_subject(conn, subject)
        .await?
        .into_iter()
        .find(|c| {
            c.is_active()
                && matches!(
                    c.kind(),
                    CredentialKind::Password | CredentialKind::EmailLink
                )
        })
        .map_or_else(|| subject.to_string(), |c| c.identifier))
}

#[derive(Deserialize)]
struct RegistrationStart {
    label: String,
}

/// `POST /v1/passkeys/registration/options`
// r[impl authn.passkey.registration]
async fn registration_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RegistrationStart>,
) -> Result<Json<Ceremony<impl Serialize>>, ApiError> {
    let verifier = verifier(&state)?;
    let label = body.label.trim().to_owned();
    if label.is_empty() || label.chars().count() > LABEL_MAX {
        return Err(ApiError::invalid_request(format!(
            "label must be 1 to {LABEL_MAX} characters"
        )));
    }
    let mut conn = state.pool.get().await?;
    let session = recent_session(&state, &mut conn, &headers).await?;
    let subject = session.subject_id;
    let since = Utc::now() - Duration::minutes(10);
    if challenges::count_since(
        &mut conn,
        Purpose::PasskeyRegister,
        &subject.to_string(),
        since,
    )
    .await?
        >= REGISTRATION_LIMIT
    {
        return Err(ApiError::new(
            ErrorCode::RateLimited,
            "too many requests; try again later",
        ));
    }
    let existing = passkeys_of(&mut conn, subject).await?;
    let existing: Vec<_> = existing.iter().filter_map(key_data).collect();
    let name = account_name(&mut conn, subject).await?;
    let (options, ceremony_state) = verifier
        .start_registration(subject, &name, &existing)
        .map_err(ApiError::internal)?;
    let details = Details {
        label: Some(label),
        state: ceremony_state,
    };
    let ceremony = begin(
        &mut conn,
        Purpose::PasskeyRegister,
        Some(subject),
        Some(&session),
        details,
    )
    .await?;
    Ok(Json(Ceremony { ceremony, options }))
}

#[derive(Deserialize)]
struct Registration {
    ceremony: String,
    credential: RegisterPublicKeyCredential,
}

/// `POST /v1/passkeys/registration`
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Registration>,
) -> Result<Response, ApiError> {
    let verifier = verifier(&state)?;
    let mut conn = state.pool.get().await?;
    let session = recent_session(&state, &mut conn, &headers).await?;
    let details = take(
        &mut conn,
        &body.ceremony,
        Purpose::PasskeyRegister,
        Some(&session),
    )
    .await?;
    let label = details.label.ok_or_else(invalid_credentials)?;
    let registered = verifier
        .finish_registration(details.state, &body.credential, label)
        .map_err(|error| rejected(&error))?;
    // r[impl credential.public-key.no-mfa]
    let credential = credentials::insert(
        &mut conn,
        NewCredential {
            id: CredentialId::new_v7(),
            subject_id: session.subject_id,
            identifier: registered.credential_id,
            data: CredentialData::PublicKey(registered.data),
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await?;
    let view = PasskeyView::of(&credential).expect("a public-key credential");
    Ok((StatusCode::CREATED, Json(view)).into_response())
}

/// `POST /v1/login/passkey/options`
async fn login_options(
    State(state): State<AppState>,
) -> Result<Json<Ceremony<impl Serialize>>, ApiError> {
    let verifier = verifier(&state)?;
    let (options, ceremony_state) = verifier.start_login().map_err(ApiError::internal)?;
    let mut conn = state.pool.get().await?;
    let details = Details {
        label: None,
        state: ceremony_state,
    };
    let ceremony = begin(&mut conn, Purpose::PasskeyLogin, None, None, details).await?;
    Ok(Json(Ceremony { ceremony, options }))
}

#[derive(Deserialize)]
struct Login {
    ceremony: String,
    credential: PublicKeyCredential,
    /// Restrictive session flags the client asks for, from the catalog's
    /// requestable ones.
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    client: Client,
}

/// `POST /v1/login/passkey`: logs in with a discoverable passkey; no login
/// identifier is needed.
// r[impl authn.login.methods]
// r[impl authn.passkey.discoverable]
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Login>,
) -> Result<Response, ApiError> {
    let verifier = verifier(&state)?;
    let browser = match body.client {
        Client::Browser => Some(check_browser_request(&state.auth, &headers)?.clone()),
        Client::Native => None,
    };
    let mut conn = state.pool.get().await?;
    check_requested_flags(&mut conn, &body.flags).await?;
    let details = take(&mut conn, &body.ceremony, Purpose::PasskeyLogin, None).await?;
    let claimed = verifier
        .claimed(&body.credential)
        .map_err(|error| rejected(&error))?;
    let kind = CredentialKind::PublicKey;
    let attempt = begin_attempt(&mut conn, kind, &claimed.credential_id).await?;

    let credential = credentials::find_active(&mut conn, kind, &claimed.credential_id)
        .await?
        // The user handle must name the key's own subject.
        .filter(|c| c.subject_id == claimed.subject);
    let subject = match &credential {
        Some(credential) => Some(subjects::get(&mut conn, credential.subject_id).await?),
        None => None,
    };
    let usable = subject
        .as_ref()
        .is_some_and(|s| s.state == SubjectState::Active && s.kind == SubjectKind::Human);
    let updated = match (&credential, usable) {
        (Some(credential), true) => key_data(credential).and_then(|stored| {
            verifier
                .finish_login(details.state, &body.credential, stored)
                .map_err(|error| tracing::debug!(%error, "passkey rejected"))
                .ok()
        }),
        _ => None,
    };
    attempt.finish(&mut conn, updated.is_some()).await?;
    // r[impl platform.error.no-enumeration]
    let (Some(credential), Some(updated)) = (credential, updated) else {
        return Err(invalid_credentials());
    };
    // r[impl authn.passkey.counter]
    credentials::set_data(
        &mut conn,
        credential.id,
        &CredentialData::PublicKey(updated),
    )
    .await?;
    start_session(
        &state,
        &mut conn,
        &credential,
        &PASSKEY_AMR,
        body.client,
        browser.as_ref(),
        &body.flags,
    )
    .await
}

/// `POST /v1/step-up/passkey/options`: starts a step-up with one of the
/// session's subject's passkeys; finish it with `POST /v1/step-up`.
async fn step_up_options(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Ceremony<impl Serialize>>, ApiError> {
    let verifier = verifier(&state)?;
    let mut conn = state.pool.get().await?;
    let session = full_session(&state, &mut conn, &headers).await?;
    let existing = passkeys_of(&mut conn, session.subject_id).await?;
    if existing.is_empty() {
        return Err(ApiError::invalid_request("the subject has no passkeys"));
    }
    let existing: Vec<_> = existing.iter().filter_map(key_data).collect();
    let (options, ceremony_state) = verifier
        .start_step_up(&existing)
        .map_err(ApiError::internal)?;
    let details = Details {
        label: None,
        state: ceremony_state,
    };
    let ceremony = begin(
        &mut conn,
        Purpose::PasskeyLogin,
        Some(session.subject_id),
        Some(&session),
        details,
    )
    .await?;
    Ok(Json(Ceremony { ceremony, options }))
}

/// Verifies a step-up assertion for `session` and records the key's use.
pub(crate) async fn verify_step_up(
    state: &AppState,
    conn: &mut Connection,
    session: &Session,
    ceremony: &str,
    credential: &PublicKeyCredential,
) -> Result<(), ApiError> {
    let verifier = verifier(state)?;
    let details = take(conn, ceremony, Purpose::PasskeyLogin, Some(session)).await?;
    let existing: Vec<(String, CredentialId, PublicKeyData)> =
        passkeys_of(conn, session.subject_id)
            .await?
            .into_iter()
            .filter_map(|c| key_data(&c).cloned().map(|data| (c.identifier, c.id, data)))
            .collect();
    let keyed: Vec<(String, PublicKeyData)> = existing
        .iter()
        .map(|(identifier, _, data)| (identifier.clone(), data.clone()))
        .collect();
    let (used, updated) = verifier
        .finish_step_up(details.state, credential, &keyed)
        .map_err(|error| rejected(&error))?;
    let id = existing
        .iter()
        .find(|(identifier, _, _)| identifier == used)
        .map(|(_, id, _)| *id)
        .ok_or_else(invalid_credentials)?;
    credentials::set_data(conn, id, &CredentialData::PublicKey(updated)).await?;
    Ok(())
}

/// `GET /v1/passkeys`: the caller's active passkeys.
// r[impl authn.passkey.management]
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PasskeyView>>, ApiError> {
    verifier(&state)?;
    let mut conn = state.pool.get().await?;
    let session = full_session(&state, &mut conn, &headers).await?;
    let passkeys = passkeys_of(&mut conn, session.subject_id).await?;
    Ok(Json(passkeys.iter().filter_map(PasskeyView::of).collect()))
}

#[derive(Serialize)]
struct Removed {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<Cursor>,
}

/// `DELETE /v1/passkeys/{id}`: revokes one of the caller's passkeys and
/// ends the other sessions started with it.
// r[impl credential.revocation-ends-sessions]
async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Removed>, ApiError> {
    verifier(&state)?;
    let id: CredentialId = id.parse().map_err(|_| ApiError::not_found("passkey"))?;
    let mut conn = state.pool.get().await?;
    let session = recent_session(&state, &mut conn, &headers).await?;
    let owned = passkeys_of(&mut conn, session.subject_id)
        .await?
        .iter()
        .any(|c| c.id == id);
    if !owned {
        return Err(ApiError::not_found("passkey"));
    }
    let keep = session.id;
    let revoked = conn
        .transaction::<_, ApiError, _>(async |conn| {
            credentials::revoke(conn, id, "removed_by_subject").await?;
            let filter = SessionFilter {
                credential: Some(id),
                ..Default::default()
            };
            Ok(sessions::revoke(conn, &filter, Some(keep), "credential_revoked").await?)
        })
        .await?;
    Ok(Json(Removed {
        cursor: revoked.last().map(|(_, cursor)| *cursor),
    }))
}
