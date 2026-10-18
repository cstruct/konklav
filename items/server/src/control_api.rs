//! The control-plane surface: subjects, credentials, sessions and signing
//! keys.
//!
//! Until operator authorization arrives (M6), every route requires the
//! configured bootstrap bearer token.

use axum::extract::{Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use conclave_authn::generate_secret;
use conclave_core::{CredentialId, Cursor, SessionId, SubjectId};
use conclave_store::credentials::{
    self, Credential, CredentialData, CredentialKind, NewCredential, PasswordData, SecretKeyData,
    SecretSlot, SecretSlotData,
};
use conclave_store::sessions::{self, Session, SessionFilter};
use conclave_store::subjects::{self, Subject, SubjectKind, SubjectState};
use conclave_store::{StoreError, signing_keys};
use diesel_async::AsyncConnection;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::{AppState, capabilities};

pub fn routes(state: &AppState) -> Router<AppState> {
    let subjects = Router::new()
        .route("/subjects", get(list_subjects))
        .route("/subjects/{id}", put(create_subject).get(get_subject))
        .route("/subjects/{id}/disable", post(disable_subject))
        .route("/subjects/{id}/enable", post(enable_subject))
        .route("/subjects/{id}/credentials", post(create_credential))
        .route("/credentials/{id}/revoke", post(revoke_credential))
        .route("/credentials/{id}/replace", post(replace_password))
        .route("/credentials/{id}/break-glass", put(set_break_glass))
        .route(
            "/credentials/{id}/slots/{slot}/rotate",
            post(rotate_secret_slot),
        )
        .route_layer(guard(state, capabilities::SUBJECTS));
    let sessions = Router::new()
        .route("/sessions", get(list_sessions))
        .route("/sessions/revoke", post(revoke_sessions))
        .route("/sessions/{id}", get(get_session))
        .route_layer(guard(state, capabilities::SESSIONS));
    let keys = Router::new()
        .route("/signing-keys", get(list_signing_keys))
        .route("/signing-keys/{kid}/revoke", post(revoke_signing_key))
        .route_layer(guard(state, capabilities::KEYS));
    subjects.merge(sessions).merge(keys)
}

/// Guards control-plane routes: the bootstrap token (when configured), or an
/// operator's access token whose subject holds `capability` or
/// `conclave:control:all`.
pub(crate) fn guard(state: &AppState, capability: &'static str) -> GuardLayer {
    middleware::from_fn_with_state(
        (state.clone(), capability),
        check_operator as fn(_, _, _) -> _,
    )
}

type GuardFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;
type GuardState = (AppState, &'static str);
type GuardLayer = axum::middleware::FromFnLayer<
    fn(State<GuardState>, Request, Next) -> GuardFuture,
    GuardState,
    (State<GuardState>, Request),
>;

// r[impl authz.control-plane.capability]
fn check_operator(
    State((state, capability)): State<(AppState, &'static str)>,
    request: Request,
    next: Next,
) -> GuardFuture {
    Box::pin(async move {
        match authorize_operator(&state, capability, request.headers()).await {
            Ok(()) => next.run(request).await,
            Err(error) => error.into_response(),
        }
    })
}

async fn authorize_operator(
    state: &AppState,
    capability: &'static str,
    headers: &axum::http::HeaderMap,
) -> Result<(), ApiError> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unauthenticated,
                "missing control-plane credentials",
            )
        })?;
    if let Some(bootstrap) = &state.auth.control_token
        && bool::from(presented.as_bytes().ct_eq(bootstrap.as_bytes()))
    {
        return Ok(());
    }
    let mut conn = state.pool.get().await?;
    let (_, session) = crate::subject_api::verify_access_token(state, &mut conn, presented)
        .await
        .map_err(|_| {
            ApiError::new(
                ErrorCode::Unauthenticated,
                "missing or invalid control-plane credentials",
            )
        })?;
    if session.stage == conclave_store::sessions::Stage::Partial {
        return Err(ApiError::new(ErrorCode::Forbidden, "complete MFA first"));
    }
    if capabilities::holds(&mut conn, session.subject_id, capabilities::CONTROL_ALL).await?
        || capabilities::holds(&mut conn, session.subject_id, capability).await?
    {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::Forbidden,
            format!("missing capability {capability}"),
        ))
    }
}

pub(crate) fn parse_id<T: std::str::FromStr>(value: &str, what: &str) -> Result<T, ApiError> {
    value
        .parse()
        .map_err(|_| ApiError::invalid_request(format!("{what} is not a valid identifier")))
}

/// A write's result and the cursor of the last event it produced, if any.
// r[impl platform.idempotency.write-cursor]
#[derive(Serialize)]
pub(crate) struct Written<T> {
    #[serde(flatten)]
    pub(crate) value: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cursor: Option<Cursor>,
}

fn last_cursor(revoked: &[(Session, Cursor)]) -> Option<Cursor> {
    revoked.last().map(|(_, cursor)| *cursor)
}

// --- Subjects ---------------------------------------------------------------

#[derive(Serialize)]
struct SubjectView {
    id: SubjectId,
    kind: SubjectKind,
    state: SubjectState,
    created_at: DateTime<Utc>,
}

impl From<Subject> for SubjectView {
    fn from(subject: Subject) -> Self {
        Self {
            id: subject.id,
            kind: subject.kind,
            state: subject.state,
            created_at: subject.created_at,
        }
    }
}

#[derive(Deserialize)]
struct SubjectQuery {
    kind: Option<SubjectKind>,
    /// A login identifier (email address, phone number or key id).
    identifier: Option<String>,
    before: Option<SubjectId>,
    limit: Option<i64>,
}

#[derive(Serialize)]
struct SubjectPage {
    subjects: Vec<SubjectView>,
    next: Option<SubjectId>,
}

/// `GET /v1/subjects?kind=&identifier=&before=&limit=`
async fn list_subjects(
    State(state): State<AppState>,
    Query(query): Query<SubjectQuery>,
) -> Result<Json<SubjectPage>, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let mut conn = state.pool.get().await?;
    let subjects = subjects::list(
        &mut conn,
        query.kind,
        query.identifier.as_deref(),
        query.before,
        limit,
    )
    .await?;
    let next = (i64::try_from(subjects.len()) == Ok(limit))
        .then(|| subjects.last().map(|s| s.id))
        .flatten();
    Ok(Json(SubjectPage {
        subjects: subjects.into_iter().map(SubjectView::from).collect(),
        next,
    }))
}

#[derive(Deserialize)]
struct CreateSubject {
    kind: SubjectKind,
}

/// `PUT /v1/subjects/{id}`: idempotent on the id.
async fn create_subject(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CreateSubject>,
) -> Result<Response, ApiError> {
    let id = parse_id(&id, "subject id")?;
    let mut conn = state.pool.get().await?;
    let (subject, created) = subjects::create(&mut conn, id, body.kind).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(SubjectView::from(subject))).into_response())
}

#[derive(Serialize)]
struct SubjectDetail {
    #[serde(flatten)]
    subject: SubjectView,
    credentials: Vec<CredentialView>,
}

async fn get_subject(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SubjectDetail>, ApiError> {
    let id = parse_id(&id, "subject id")?;
    let mut conn = state.pool.get().await?;
    let subject = subjects::get(&mut conn, id)
        .await
        .map_err(|_| ApiError::not_found("subject"))?;
    let credentials = credentials::list_for_subject(&mut conn, id).await?;
    Ok(Json(SubjectDetail {
        subject: subject.into(),
        credentials: credentials.into_iter().map(CredentialView::from).collect(),
    }))
}

async fn set_subject_state(
    state: &AppState,
    id: &str,
    target: SubjectState,
) -> Result<Json<Written<SubjectView>>, ApiError> {
    let id = parse_id(id, "subject id")?;
    let mut conn = state.pool.get().await?;
    let revoked = conn
        .transaction::<_, ApiError, _>(async |conn| {
            subjects::set_state(conn, id, target)
                .await
                .map_err(|error| match error {
                    StoreError::NotFound => ApiError::not_found("subject"),
                    other => other.into(),
                })?;
            if target == SubjectState::Disabled {
                // r[impl subject.state]
                let filter = SessionFilter {
                    subject: Some(id),
                    ..Default::default()
                };
                return Ok(sessions::revoke(conn, &filter, None, "subject_disabled").await?);
            }
            Ok(Vec::new())
        })
        .await?;
    let subject = subjects::get(&mut conn, id).await?;
    Ok(Json(Written {
        value: subject.into(),
        cursor: last_cursor(&revoked),
    }))
}

async fn disable_subject(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Written<SubjectView>>, ApiError> {
    set_subject_state(&state, &id, SubjectState::Disabled).await
}

async fn enable_subject(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Written<SubjectView>>, ApiError> {
    set_subject_state(&state, &id, SubjectState::Active).await
}

// --- Credentials ------------------------------------------------------------

#[derive(Serialize)]
struct SlotView {
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl From<&SecretSlotData> for SlotView {
    fn from(slot: &SecretSlotData) -> Self {
        Self {
            created_at: slot.created_at,
            expires_at: slot.expires_at,
        }
    }
}

#[derive(Serialize)]
struct SlotsView {
    a: SlotView,
    b: SlotView,
}

/// A credential without any secret material.
#[derive(Serialize)]
struct CredentialView {
    id: CredentialId,
    subject_id: SubjectId,
    kind: CredentialKind,
    identifier: String,
    mfa_factors_required: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    slots: Option<SlotsView>,
    replaces: Option<CredentialId>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_reason: Option<String>,
    break_glass: bool,
}

impl From<Credential> for CredentialView {
    fn from(credential: Credential) -> Self {
        let slots = match &credential.data {
            CredentialData::SecretKey(data) => Some(SlotsView {
                a: SlotView::from(&data.a),
                b: SlotView::from(&data.b),
            }),
            CredentialData::Password(_)
            | CredentialData::EmailLink
            | CredentialData::PhoneOtp
            | CredentialData::Federated(_)
            | CredentialData::Client => None,
        };
        Self {
            id: credential.id,
            subject_id: credential.subject_id,
            kind: credential.kind(),
            identifier: credential.identifier,
            mfa_factors_required: credential.mfa_factors_required,
            slots,
            replaces: credential.replaces,
            created_at: credential.created_at,
            revoked_at: credential.revoked_at,
            revoked_reason: credential.revoked_reason,
            break_glass: credential.break_glass,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CreateCredential {
    Password {
        id: Option<CredentialId>,
        identifier: String,
        password: String,
        #[serde(default)]
        mfa_factors_required: i16,
    },
    SecretKey {
        id: Option<CredentialId>,
        expires_at: Option<DateTime<Utc>>,
    },
    /// Log in with a magic link sent to `identifier`, an email address.
    EmailLink {
        id: Option<CredentialId>,
        identifier: String,
    },
    /// Log in with a code sent to `identifier`, an E.164 phone number.
    PhoneOtp {
        id: Option<CredentialId>,
        identifier: String,
    },
}

#[derive(Serialize)]
struct CreatedCredential {
    credential: CredentialView,
    /// For secret keys: both slots' `<key id>.<secret>`, shown only once.
    // r[impl credential.secret-key.hashed]
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_keys: Option<SecretKeys>,
}

#[derive(Serialize)]
struct SecretKeys {
    a: String,
    b: String,
}

#[derive(Serialize)]
struct RotatedSlot {
    credential: CredentialView,
    slot: SecretSlot,
    /// The slot's new `<key id>.<secret>`, shown only once.
    secret_key: String,
}

/// A new secret and its slot data.
async fn new_slot(
    state: &AppState,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(String, SecretSlotData), ApiError> {
    let secret = generate_secret();
    let data = SecretSlotData {
        hash: hash(state, secret.clone()).await?,
        created_at: Utc::now(),
        expires_at,
    };
    Ok((secret, data))
}

async fn hash(state: &AppState, secret: String) -> Result<String, ApiError> {
    let hasher = state.auth.hasher.clone();
    tokio::task::spawn_blocking(move || hasher.hash(&secret))
        .await
        .map_err(ApiError::internal)
}

const MIN_PASSWORD_LENGTH: usize = 8;

/// `POST /v1/subjects/{id}/credentials`
async fn create_credential(
    State(state): State<AppState>,
    Path(subject_id): Path<String>,
    ApiJson(body): ApiJson<CreateCredential>,
) -> Result<(StatusCode, Json<CreatedCredential>), ApiError> {
    let subject_id: SubjectId = parse_id(&subject_id, "subject id")?;
    let mut conn = state.pool.get().await?;
    let subject = subjects::get(&mut conn, subject_id)
        .await
        .map_err(|_| ApiError::not_found("subject"))?;

    let is_email = matches!(body, CreateCredential::EmailLink { .. });
    let (new, secret_keys) = match body {
        CreateCredential::Password {
            id,
            identifier,
            password,
            mfa_factors_required,
        } => {
            if subject.kind != SubjectKind::Human {
                return Err(ApiError::invalid_request(
                    "service principals cannot have passwords",
                ));
            }
            if identifier.trim().is_empty() {
                return Err(ApiError::invalid_request("identifier must not be empty"));
            }
            if password.chars().count() < MIN_PASSWORD_LENGTH {
                return Err(ApiError::invalid_request(format!(
                    "passwords need at least {MIN_PASSWORD_LENGTH} characters"
                )));
            }
            if mfa_factors_required < 0 {
                return Err(ApiError::invalid_request(
                    "mfa_factors_required must not be negative",
                ));
            }
            let hash = hash(&state, password).await?;
            let new = NewCredential {
                id: id.unwrap_or_else(CredentialId::new_v7),
                subject_id,
                identifier,
                data: CredentialData::Password(PasswordData { hash }),
                mfa_factors_required,
                replaces: None,
            };
            (new, None)
        }
        CreateCredential::EmailLink { id, identifier }
        | CreateCredential::PhoneOtp { id, identifier } => (
            passwordless_credential(&subject, id, identifier, is_email)?,
            None,
        ),
        CreateCredential::SecretKey { id, expires_at } => {
            if subject.kind != SubjectKind::Service {
                return Err(ApiError::invalid_request(
                    "only service principals can have secret keys",
                ));
            }
            let id = id.unwrap_or_else(CredentialId::new_v7);
            let (secret_a, a) = new_slot(&state, expires_at).await?;
            let (secret_b, b) = new_slot(&state, expires_at).await?;
            let new = NewCredential {
                id,
                subject_id,
                identifier: id.to_string(),
                data: CredentialData::SecretKey(SecretKeyData { a, b }),
                mfa_factors_required: 0,
                replaces: None,
            };
            let keys = SecretKeys {
                a: format!("{id}.{secret_a}"),
                b: format!("{id}.{secret_b}"),
            };
            (new, Some(keys))
        }
    };
    let credential = credentials::insert(&mut conn, new).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedCredential {
            credential: credential.into(),
            secret_keys,
        }),
    ))
}

/// A magic-link (`email`) or phone-code credential for a person.
fn passwordless_credential(
    subject: &Subject,
    id: Option<CredentialId>,
    identifier: String,
    email: bool,
) -> Result<NewCredential, ApiError> {
    if subject.kind != SubjectKind::Human {
        return Err(ApiError::invalid_request(
            "service principals cannot use interactive credentials",
        ));
    }
    let valid = if email {
        identifier.contains('@')
    } else {
        identifier.len() > 7
            && identifier.starts_with('+')
            && identifier[1..].chars().all(|c| c.is_ascii_digit())
    };
    if !valid {
        return Err(ApiError::invalid_request(if email {
            "identifier must be an email address"
        } else {
            "identifier must be an E.164 phone number"
        }));
    }
    Ok(NewCredential {
        id: id.unwrap_or_else(CredentialId::new_v7),
        subject_id: subject.id,
        identifier,
        data: if email {
            CredentialData::EmailLink
        } else {
            CredentialData::PhoneOtp
        },
        mfa_factors_required: 0,
        replaces: None,
    })
}

#[derive(Default, Deserialize)]
struct RevokeCredential {
    reason: Option<String>,
}

/// `POST /v1/credentials/{id}/revoke`: revokes the credential and ends the
/// sessions established with it.
// r[impl credential.revocation-ends-sessions]
async fn revoke_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<ApiJson<RevokeCredential>>,
) -> Result<Json<Written<CredentialView>>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let reason = body
        .and_then(|ApiJson(body)| body.reason)
        .unwrap_or_else(|| "revoked".to_owned());
    let mut conn = state.pool.get().await?;
    let revoked = conn
        .transaction::<_, ApiError, _>(async |conn| {
            credentials::revoke(conn, id, &reason)
                .await
                .map_err(|error| match error {
                    StoreError::NotFound => ApiError::not_found("credential"),
                    other => other.into(),
                })?;
            let filter = SessionFilter {
                credential: Some(id),
                ..Default::default()
            };
            Ok(sessions::revoke(conn, &filter, None, "credential_revoked").await?)
        })
        .await?;
    let credential = credentials::get(&mut conn, id).await?;
    Ok(Json(Written {
        value: credential.into(),
        cursor: last_cursor(&revoked),
    }))
}

#[derive(Deserialize)]
struct ReplacePassword {
    password: String,
    id: Option<CredentialId>,
}

/// `POST /v1/credentials/{id}/replace`: replaces a password with a new
/// credential that records what it replaces. Sessions established with the
/// old one end.
async fn replace_password(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ReplacePassword>,
) -> Result<(StatusCode, Json<Written<CredentialView>>), ApiError> {
    let old_id: CredentialId = parse_id(&id, "credential id")?;
    if body.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ApiError::invalid_request(format!(
            "passwords need at least {MIN_PASSWORD_LENGTH} characters"
        )));
    }
    let hash = hash(&state, body.password).await?;
    let new_id = body.id.unwrap_or_else(CredentialId::new_v7);
    let mut conn = state.pool.get().await?;
    let (credential, revoked) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let old = credentials::get_for_update(conn, old_id)
                .await
                .map_err(|_| ApiError::not_found("credential"))?;
            if old.kind() != CredentialKind::Password || !old.is_active() {
                return Err(ApiError::invalid_request(
                    "only active passwords can be replaced",
                ));
            }
            credentials::revoke(conn, old_id, "replaced").await?;
            let credential = credentials::insert(
                conn,
                NewCredential {
                    id: new_id,
                    subject_id: old.subject_id,
                    identifier: old.identifier.clone(),
                    data: CredentialData::Password(PasswordData { hash }),
                    mfa_factors_required: old.mfa_factors_required,
                    replaces: Some(old_id),
                },
            )
            .await?;
            let filter = SessionFilter {
                credential: Some(old_id),
                ..Default::default()
            };
            let revoked = sessions::revoke(conn, &filter, None, "credential_replaced").await?;
            Ok((credential, revoked))
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(Written {
            value: credential.into(),
            cursor: last_cursor(&revoked),
        }),
    ))
}

#[derive(Default, Deserialize)]
struct RotateSlot {
    expires_at: Option<DateTime<Utc>>,
}

/// `POST /v1/credentials/{id}/slots/{slot}/rotate`: sets a new secret for
/// one slot of a secret key. The other slot keeps working, so clients can
/// switch over without downtime.
async fn rotate_secret_slot(
    State(state): State<AppState>,
    Path((id, slot)): Path<(String, String)>,
    body: Option<ApiJson<RotateSlot>>,
) -> Result<Json<RotatedSlot>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let slot = match slot.as_str() {
        "a" => SecretSlot::A,
        "b" => SecretSlot::B,
        _ => return Err(ApiError::invalid_request("slot must be a or b")),
    };
    let expires_at = body.and_then(|ApiJson(body)| body.expires_at);
    let (secret, slot_data) = new_slot(&state, expires_at).await?;
    let mut conn = state.pool.get().await?;
    let credential = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let credential = credentials::get_for_update(conn, id)
                .await
                .map_err(|_| ApiError::not_found("credential"))?;
            let CredentialData::SecretKey(mut data) = credential.data.clone() else {
                return Err(ApiError::invalid_request("only secret keys have slots"));
            };
            if !credential.is_active() {
                return Err(ApiError::invalid_request("the credential is revoked"));
            }
            data.set(slot, slot_data);
            credentials::set_data(conn, id, &CredentialData::SecretKey(data)).await?;
            Ok(credentials::get(conn, id).await?)
        })
        .await?;
    Ok(Json(RotatedSlot {
        credential: credential.into(),
        slot,
        secret_key: format!("{id}.{secret}"),
    }))
}

// --- Sessions ---------------------------------------------------------------

#[derive(Deserialize)]
struct SessionQuery {
    subject: Option<SubjectId>,
    credential: Option<CredentialId>,
    #[serde(default)]
    active: bool,
    before: Option<SessionId>,
    limit: Option<i64>,
}

#[derive(Serialize)]
struct SessionPage {
    sessions: Vec<Session>,
    /// Pass as `before` to get the next page.
    next: Option<SessionId>,
}

/// `GET /v1/sessions`
// r[impl session.admin]
async fn list_sessions(
    State(state): State<AppState>,
    Query(query): Query<SessionQuery>,
) -> Result<Json<SessionPage>, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let filter = SessionFilter {
        subject: query.subject,
        credential: query.credential,
        ..Default::default()
    };
    let mut conn = state.pool.get().await?;
    let active_at = query.active.then(Utc::now);
    let sessions = sessions::list(&mut conn, &filter, active_at, query.before, limit).await?;
    let next = (i64::try_from(sessions.len()) == Ok(limit))
        .then(|| sessions.last().map(|s| s.id))
        .flatten();
    Ok(Json(SessionPage { sessions, next }))
}

async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Session>, ApiError> {
    let id = parse_id(&id, "session id")?;
    let mut conn = state.pool.get().await?;
    Ok(Json(
        sessions::get(&mut conn, id)
            .await
            .map_err(|_| ApiError::not_found("session"))?,
    ))
}

#[derive(Deserialize)]
struct RevokeSessions {
    #[serde(flatten)]
    filter: SessionFilter,
    keep: Option<SessionId>,
    reason: Option<String>,
}

#[derive(Serialize)]
struct RevokedSessions {
    revoked: Vec<SessionId>,
}

/// `POST /v1/sessions/revoke`
async fn revoke_sessions(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<RevokeSessions>,
) -> Result<Json<Written<RevokedSessions>>, ApiError> {
    if body.filter.is_empty() {
        return Err(ApiError::invalid_request(
            "name at least one of session, subject, credential, tenant or membership",
        ));
    }
    let reason = body
        .reason
        .unwrap_or_else(|| "revoked_by_operator".to_owned());
    let mut conn = state.pool.get().await?;
    let revoked = sessions::revoke(&mut conn, &body.filter, body.keep, &reason).await?;
    Ok(Json(Written {
        value: RevokedSessions {
            revoked: revoked.iter().map(|(s, _)| s.id).collect(),
        },
        cursor: last_cursor(&revoked),
    }))
}

// --- Signing keys -----------------------------------------------------------

async fn list_signing_keys(
    State(state): State<AppState>,
) -> Result<Json<Vec<signing_keys::SigningKey>>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(signing_keys::list(&mut conn).await?))
}

#[derive(Serialize)]
struct RevokedKey {
    kid: String,
    revoked: bool,
}

/// `POST /v1/signing-keys/{kid}/revoke`: break-glass revocation.
async fn revoke_signing_key(
    State(state): State<AppState>,
    Path(kid): Path<String>,
) -> Result<Json<RevokedKey>, ApiError> {
    let mut conn = state.pool.get().await?;
    let revoked = signing_keys::revoke(&mut conn, &kid)
        .await
        .map_err(|error| match error {
            StoreError::NotFound => ApiError::not_found("signing key"),
            other => other.into(),
        })?;
    Ok(Json(RevokedKey { kid, revoked }))
}

#[derive(Deserialize)]
struct BreakGlass {
    break_glass: bool,
}

/// `PUT /v1/credentials/{id}/break-glass`: marks a local password or secret
/// key as a break-glass credential, whose every use appends
/// `break_glass.used`.
async fn set_break_glass(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<BreakGlass>,
) -> Result<Json<CredentialView>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let mut conn = state.pool.get().await?;
    let credential = credentials::get(&mut conn, id)
        .await
        .map_err(|_| ApiError::not_found("credential"))?;
    if !matches!(
        credential.kind(),
        CredentialKind::Password | CredentialKind::SecretKey
    ) || !credential.is_active()
    {
        return Err(ApiError::invalid_request(
            "only active passwords and secret keys can be break-glass credentials",
        ));
    }
    credentials::set_break_glass(&mut conn, id, body.break_glass).await?;
    Ok(Json(credentials::get(&mut conn, id).await?.into()))
}
