//! The control-plane surface: subjects, credentials, sessions and signing
//! keys.
//!
//! Until operator authorization arrives (M6), every route requires the
//! configured bootstrap bearer token.

use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use diesel_async::AsyncConnection;
use konklav_api::{
    self as api, BreakGlass, CreateCredential, CreateSubject, CreatedCredential, ReplacePassword,
    RevokeCredential, RevokeSessions, RevokedKey, RevokedSessions, RotateSlot, RotatedSlot,
    SecretKeys, SessionFlags, SessionPage, SessionQuery, SubjectDetail, SubjectPage, SubjectQuery,
};
use konklav_authn::{PasswordHasher, generate_secret};
use konklav_core::{CredentialId, Cursor, SessionId, SubjectId};
use konklav_store::credentials::{
    self, CredentialData, CredentialKind, NewCredential, PasswordData, SecretKeyData, SecretSlot,
    SecretSlotData,
};
use konklav_store::sessions::{self, Session, SessionFilter};
use konklav_store::subjects::{self, Subject, SubjectKind, SubjectState};
use konklav_store::{StoreError, signing_keys};
use subtle::ConstantTimeEq;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub(crate) use konklav_api::Written;

use crate::capabilities::Operator;
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::{AppState, capabilities, subject_api, transport};

/// Subjects and their credentials, with the `OpenAPI` description of each
/// route taken from its handler's `#[utoipa::path]`.
pub(crate) fn subjects() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_subjects))
        .routes(routes!(create_subject, get_subject))
        .routes(routes!(disable_subject))
        .routes(routes!(enable_subject))
        .routes(routes!(create_credential))
        .routes(routes!(revoke_credential))
        .routes(routes!(replace_password))
        .routes(routes!(set_break_glass))
        .routes(routes!(set_session_flags))
        .routes(routes!(rotate_secret_slot))
}

/// Sessions, described like [`subjects`].
pub(crate) fn sessions() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_sessions))
        .routes(routes!(revoke_sessions))
        .routes(routes!(get_session))
}

/// Signing keys, described like [`subjects`].
pub(crate) fn signing_keys() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_signing_keys))
        .routes(routes!(revoke_signing_key))
}

pub fn routes(state: &AppState) -> Router<AppState> {
    let (subjects, _) = subjects()
        .route_layer(guard(state, capabilities::SUBJECTS))
        .split_for_parts();
    let (sessions, _) = sessions()
        .route_layer(guard(state, capabilities::SESSIONS))
        .split_for_parts();
    let (keys, _) = signing_keys()
        .route_layer(guard(state, capabilities::KEYS))
        .split_for_parts();
    subjects.merge(sessions).merge(keys)
}

/// Guards control-plane routes: the bootstrap token (when configured), or an
/// operator's access token whose subject holds `capability` or
/// `konklav:control:all`.
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
        let mut request = request;
        match authorize_operator(&state, capability, request.headers()).await {
            Ok(operator) => {
                request.extensions_mut().insert(operator);
                next.run(request).await
            }
            Err(error) => error.into_response(),
        }
    })
}

async fn authorize_operator(
    state: &AppState,
    capability: &'static str,
    headers: &axum::http::HeaderMap,
) -> Result<Operator, ApiError> {
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
    // r[impl platform.config.bootstrap-token]
    if let Some(bootstrap) = &state.auth.control_token
        && bool::from(presented.as_bytes().ct_eq(bootstrap.as_bytes()))
        && state
            .auth
            .control_token_expires_at
            .is_none_or(|expires| Utc::now() < expires)
    {
        tracing::info!(capability, "control plane used with the bootstrap token");
        return Ok(Operator { all: true });
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
    if session.stage == konklav_store::sessions::Stage::Partial {
        return Err(ApiError::new(ErrorCode::Forbidden, "complete MFA first"));
    }
    crate::subject_api::refuse_impersonation(&session)?;
    let all = capabilities::holds(&mut conn, session.subject_id, capabilities::CONTROL_ALL).await?;
    if all || capabilities::holds(&mut conn, session.subject_id, capability).await? {
        Ok(Operator { all })
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

fn last_cursor(revoked: &[(Session, Cursor)]) -> Option<Cursor> {
    revoked.last().map(|(_, cursor)| *cursor)
}

// --- Subjects ---------------------------------------------------------------

/// `GET /v1/subjects?kind=&identifier=&before=&limit=`
#[utoipa::path(get, path = "/subjects", tag = "subjects", params(SubjectQuery),
    responses((status = 200, body = SubjectPage)))]
async fn list_subjects(
    State(state): State<AppState>,
    Query(query): Query<SubjectQuery>,
) -> Result<Json<SubjectPage>, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let mut conn = state.pool.get().await?;
    let subjects = subjects::list(
        &mut conn,
        query.kind.map(transport::store_subject_kind),
        query.identifier.as_deref(),
        query.before,
        limit,
    )
    .await?;
    let next = (i64::try_from(subjects.len()) == Ok(limit))
        .then(|| subjects.last().map(|s| s.id))
        .flatten();
    Ok(Json(SubjectPage {
        subjects: subjects.iter().map(transport::subject).collect(),
        next,
    }))
}

/// `PUT /v1/subjects/{id}`: idempotent on the id.
#[utoipa::path(put, path = "/subjects/{id}", tag = "subjects",
    params(("id" = SubjectId, Path, description = "Chosen by the caller")),
    request_body = CreateSubject,
    responses(
        (status = 201, description = "Created", body = api::Subject),
        (status = 200, description = "Already existed with the same kind", body = api::Subject),
    ))]
async fn create_subject(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CreateSubject>,
) -> Result<Response, ApiError> {
    let id = parse_id(&id, "subject id")?;
    let mut conn = state.pool.get().await?;
    let (subject, created) =
        subjects::create(&mut conn, id, transport::store_subject_kind(body.kind)).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(transport::subject(&subject))).into_response())
}

#[utoipa::path(get, path = "/subjects/{id}", tag = "subjects", params(("id" = SubjectId, Path)),
    responses((status = 200, body = SubjectDetail)))]
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
        subject: transport::subject(&subject),
        credentials: credentials.into_iter().map(transport::credential).collect(),
    }))
}

async fn set_subject_state(
    state: &AppState,
    operator: Operator,
    id: &str,
    target: SubjectState,
) -> Result<Json<Written<api::Subject>>, ApiError> {
    let id = parse_id(id, "subject id")?;
    let mut conn = state.pool.get().await?;
    operator.may_change(&mut conn, id).await?;
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
        value: transport::subject(&subject),
        cursor: last_cursor(&revoked),
    }))
}

/// Disables the subject and ends its sessions.
#[utoipa::path(post, path = "/subjects/{id}/disable", tag = "subjects", params(("id" = SubjectId, Path)),
    responses((status = 200, body = Written<api::Subject>)))]
async fn disable_subject(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
) -> Result<Json<Written<api::Subject>>, ApiError> {
    set_subject_state(&state, operator, &id, SubjectState::Disabled).await
}

#[utoipa::path(post, path = "/subjects/{id}/enable", tag = "subjects", params(("id" = SubjectId, Path)),
    responses((status = 200, body = Written<api::Subject>)))]
async fn enable_subject(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
) -> Result<Json<Written<api::Subject>>, ApiError> {
    set_subject_state(&state, operator, &id, SubjectState::Active).await
}

// --- Credentials ------------------------------------------------------------

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
    state.auth.hashing(move |hasher| hasher.hash(&secret)).await
}

const MIN_PASSWORD_LENGTH: usize = 8;

/// The stored hash for a new password credential: `password` hashed here,
/// or an Argon2id `password_hash` hashed elsewhere, kept as given.
// r[impl credential.password.hash-input]
async fn password_hash_for(
    state: &AppState,
    password: Option<String>,
    password_hash: Option<String>,
) -> Result<String, ApiError> {
    match (password, password_hash) {
        (Some(password), None) => {
            if password.chars().count() < MIN_PASSWORD_LENGTH {
                return Err(ApiError::invalid_request(format!(
                    "passwords need at least {MIN_PASSWORD_LENGTH} characters"
                )));
            }
            hash(state, password).await
        }
        (None, Some(stored)) => {
            let stored = stored.trim().to_owned();
            if PasswordHasher::is_argon2id(&stored) {
                Ok(stored)
            } else {
                Err(ApiError::invalid_request(
                    "password_hash must be an Argon2id PHC string",
                ))
            }
        }
        _ => Err(ApiError::invalid_request(
            "give either password or password_hash",
        )),
    }
}

/// `POST /v1/subjects/{id}/credentials`
// r[impl credential.secret-key.hashed]
#[utoipa::path(post, path = "/subjects/{id}/credentials", tag = "credentials",
    params(("id" = SubjectId, Path)),
    request_body = CreateCredential,
    responses((status = 201, description = "Created. A secret key's secrets are in `secret_keys`, shown only once.", body = CreatedCredential)))]
async fn create_credential(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(subject_id): Path<String>,
    ApiJson(body): ApiJson<CreateCredential>,
) -> Result<(StatusCode, Json<CreatedCredential>), ApiError> {
    let subject_id: SubjectId = parse_id(&subject_id, "subject id")?;
    let mut conn = state.pool.get().await?;
    let subject = subjects::get(&mut conn, subject_id)
        .await
        .map_err(|_| ApiError::not_found("subject"))?;
    operator.may_change(&mut conn, subject_id).await?;

    let is_email = matches!(body, CreateCredential::EmailLink { .. });
    let (new, secret_keys) = match body {
        CreateCredential::Password {
            id,
            identifier,
            password,
            password_hash,
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
            if mfa_factors_required < 0 {
                return Err(ApiError::invalid_request(
                    "mfa_factors_required must not be negative",
                ));
            }
            let hash = password_hash_for(&state, password, password_hash).await?;
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
        CreateCredential::Federated {
            id,
            provider,
            subject: upstream,
        } => (
            workload_credential(&state, &subject, id, provider, upstream)?,
            None,
        ),
    };
    let credential = credentials::insert(&mut conn, new).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedCredential {
            credential: transport::credential(credential),
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

/// `POST /v1/credentials/{id}/revoke`: revokes the credential and ends the
/// sessions established with it.
// r[impl credential.revocation-ends-sessions]
#[utoipa::path(post, path = "/credentials/{id}/revoke", tag = "credentials",
    params(("id" = CredentialId, Path)),
    request_body(content = Option<RevokeCredential>, description = "Optional"),
    responses((status = 200, body = Written<api::Credential>)))]
async fn revoke_credential(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    body: Option<ApiJson<RevokeCredential>>,
) -> Result<Json<Written<api::Credential>>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let reason = body
        .and_then(|ApiJson(body)| body.reason)
        .unwrap_or_else(|| "revoked".to_owned());
    let mut conn = state.pool.get().await?;
    if let Ok(credential) = credentials::get(&mut conn, id).await {
        operator
            .may_change(&mut conn, credential.subject_id)
            .await?;
    }
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
        value: transport::credential(credential),
        cursor: last_cursor(&revoked),
    }))
}

/// `POST /v1/credentials/{id}/replace`: replaces a password with a new
/// credential that records what it replaces. Sessions established with the
/// old one end.
#[utoipa::path(post, path = "/credentials/{id}/replace", tag = "credentials",
    params(("id" = CredentialId, Path, description = "The password to replace")),
    request_body = ReplacePassword,
    responses((status = 201, description = "The new password credential", body = Written<api::Credential>)))]
async fn replace_password(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ReplacePassword>,
) -> Result<(StatusCode, Json<Written<api::Credential>>), ApiError> {
    let old_id: CredentialId = parse_id(&id, "credential id")?;
    if body.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ApiError::invalid_request(format!(
            "passwords need at least {MIN_PASSWORD_LENGTH} characters"
        )));
    }
    let mut conn = state.pool.get().await?;
    // Outside the transaction: entitlement compilation opens its own.
    if let Ok(old) = credentials::get(&mut conn, old_id).await {
        operator.may_change(&mut conn, old.subject_id).await?;
    }
    let hash = hash(&state, body.password).await?;
    let new_id = body.id.unwrap_or_else(CredentialId::new_v7);
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
            value: transport::credential(credential),
            cursor: last_cursor(&revoked),
        }),
    ))
}

/// `POST /v1/credentials/{id}/slots/{slot}/rotate`: sets a new secret for
/// one slot of a secret key. The other slot keeps working, so clients can
/// switch over without downtime.
#[utoipa::path(post, path = "/credentials/{id}/slots/{slot}/rotate", tag = "credentials",
    params(("id" = CredentialId, Path), ("slot" = api::SecretSlot, Path)),
    request_body(content = Option<RotateSlot>, description = "Optional; without it the new secret never expires"),
    responses((status = 200, description = "Rotated. The slot's new secret is in `secret_key`, shown only once.", body = RotatedSlot)))]
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
        credential: transport::credential(credential),
        slot: transport::secret_slot(slot),
        secret_key: format!("{id}.{secret}"),
    }))
}

// --- Sessions ---------------------------------------------------------------

/// `GET /v1/sessions`
// r[impl session.admin]
#[utoipa::path(get, path = "/sessions", tag = "sessions", params(SessionQuery),
    responses((status = 200, body = SessionPage)))]
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
    Ok(Json(SessionPage {
        sessions: sessions.into_iter().map(transport::session).collect(),
        next,
    }))
}

#[utoipa::path(get, path = "/sessions/{id}", tag = "sessions", params(("id" = SessionId, Path)),
    responses((status = 200, body = api::Session)))]
async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<api::Session>, ApiError> {
    let id = parse_id(&id, "session id")?;
    let mut conn = state.pool.get().await?;
    Ok(Json(transport::session(
        sessions::get(&mut conn, id)
            .await
            .map_err(|_| ApiError::not_found("session"))?,
    )))
}

/// `POST /v1/sessions/revoke`
#[utoipa::path(post, path = "/sessions/revoke", tag = "sessions",
    request_body = RevokeSessions,
    responses((status = 200, body = Written<RevokedSessions>)))]
async fn revoke_sessions(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<RevokeSessions>,
) -> Result<Json<Written<RevokedSessions>>, ApiError> {
    let filter = transport::session_filter(&body.filter);
    if filter.is_empty() {
        return Err(ApiError::invalid_request(
            "name at least one of session, subject, credential, tenant or membership",
        ));
    }
    let reason = body
        .reason
        .unwrap_or_else(|| "revoked_by_operator".to_owned());
    let mut conn = state.pool.get().await?;
    let revoked = sessions::revoke(&mut conn, &filter, body.keep, &reason).await?;
    Ok(Json(Written {
        value: RevokedSessions {
            revoked: revoked.iter().map(|(s, _)| s.id).collect(),
        },
        cursor: last_cursor(&revoked),
    }))
}

// --- Signing keys -----------------------------------------------------------

#[utoipa::path(get, path = "/signing-keys", tag = "signing-keys",
    responses((status = 200, body = Vec<api::SigningKey>)))]
async fn list_signing_keys(
    State(state): State<AppState>,
) -> Result<Json<Vec<api::SigningKey>>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(
        signing_keys::list(&mut conn)
            .await?
            .into_iter()
            .map(transport::signing_key)
            .collect(),
    ))
}

/// `POST /v1/signing-keys/{kid}/revoke`: break-glass revocation.
#[utoipa::path(post, path = "/signing-keys/{kid}/revoke", tag = "signing-keys",
    params(("kid" = String, Path)),
    responses((status = 200, body = RevokedKey)))]
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

/// A federated credential naming a workload at an identity provider, for
/// the JWT bearer grant. Only service principals get them; people link
/// accounts by signing in.
// r[impl federation.jwt-bearer]
fn workload_credential(
    state: &AppState,
    subject: &konklav_store::subjects::Subject,
    id: Option<CredentialId>,
    provider: String,
    upstream: String,
) -> Result<NewCredential, ApiError> {
    if subject.kind != SubjectKind::Service {
        return Err(ApiError::invalid_request(
            "people link identity-provider accounts by signing in; only service principals get workload identities",
        ));
    }
    if state.auth.identity_providers.get(&provider).is_none() {
        return Err(ApiError::invalid_request("unknown identity provider"));
    }
    Ok(NewCredential {
        id: id.unwrap_or_else(CredentialId::new_v7),
        subject_id: subject.id,
        identifier: credentials::federated_identifier(&provider, &upstream),
        data: CredentialData::Federated(credentials::FederatedData {
            provider,
            subject: upstream,
            email: None,
            email_verified: None,
        }),
        mfa_factors_required: 0,
        replaces: None,
    })
}

/// `PUT /v1/credentials/{id}/session-flags`: sets the restrictive session
/// flags every session started with the credential carries.
#[utoipa::path(put, path = "/credentials/{id}/session-flags", tag = "credentials",
    params(("id" = CredentialId, Path)),
    request_body = SessionFlags,
    responses((status = 200, body = api::Credential)))]
async fn set_session_flags(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<SessionFlags>,
) -> Result<Json<api::Credential>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let mut conn = state.pool.get().await?;
    let credential = credentials::get(&mut conn, id)
        .await
        .map_err(|_| ApiError::not_found("credential"))?;
    operator
        .may_change(&mut conn, credential.subject_id)
        .await?;
    subject_api::check_credential_flags(&mut conn, &body.session_flags).await?;
    credentials::set_session_flags(&mut conn, id, &body.session_flags).await?;
    Ok(Json(transport::credential(
        credentials::get(&mut conn, id).await?,
    )))
}

/// `PUT /v1/credentials/{id}/break-glass`: marks a local password or secret
/// key as a break-glass credential, whose every use appends
/// `break_glass.used`.
#[utoipa::path(put, path = "/credentials/{id}/break-glass", tag = "credentials",
    params(("id" = CredentialId, Path)),
    request_body = BreakGlass,
    responses((status = 200, body = api::Credential)))]
async fn set_break_glass(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<BreakGlass>,
) -> Result<Json<api::Credential>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let mut conn = state.pool.get().await?;
    let credential = credentials::get(&mut conn, id)
        .await
        .map_err(|_| ApiError::not_found("credential"))?;
    operator
        .may_change(&mut conn, credential.subject_id)
        .await?;
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
    Ok(Json(transport::credential(
        credentials::get(&mut conn, id).await?,
    )))
}
