//! The control-plane surface: subjects, credentials, sessions and signing
//! keys, and the route groups and guards for the whole surface.
//!
//! Every route needs an operator: the bootstrap token, when configured, or
//! an access token whose subject holds the route group's capability
//! (`konklav:control:all` holds them all). The batch route needs only an
//! operator, since each of its operations is guarded on its own.

use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use diesel_async::AsyncConnection;
use konklav_api::{
    self as api, BreakGlass, CreateCredential, CreateSubject, CreatedCredential,
    PersonalDataReport, ReplacePassword, RevokeCredential, RevokeSessions, RevokedKey,
    RevokedSessions, RotateSlot, RotatedSlot, SecretKeys, SessionFlags, SessionPage, SessionQuery,
    SlotExpiry, SubjectDetail, SubjectPage, SubjectQuery,
};
use konklav_authn::{PasswordCheck, PasswordHasher, generate_secret};
use konklav_core::{CredentialId, Cursor, SessionId, SubjectId};
use konklav_store::credentials::{
    self, Credential, CredentialData, CredentialKind, NewCredential, PasswordData, SecretKeyData,
    SecretSlot, SecretSlotData,
};
use konklav_store::sessions::{self, Session, SessionFilter};
use konklav_store::subjects::{self, Subject, SubjectKind, SubjectState};
use konklav_store::{StoreError, mfa, personal_data, signing_keys};
use subtle::ConstantTimeEq;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub(crate) use konklav_api::Written;

use crate::capabilities::Operator;
use crate::db::Db;
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::{AppState, batch_api, capabilities, metadata, subject_api, transport};

/// Subjects and their credentials, with the `OpenAPI` description of each
/// route taken from its handler's `#[utoipa::path]`.
pub(crate) fn subjects() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_subjects))
        .routes(routes!(create_subject, get_subject))
        .routes(routes!(personal_data))
        .routes(routes!(disable_subject))
        .routes(routes!(enable_subject))
        .routes(routes!(create_credential))
        .routes(routes!(revoke_credential))
        .routes(routes!(replace_password))
        .routes(routes!(set_break_glass))
        .routes(routes!(set_session_flags))
        .routes(routes!(rotate_secret_slot))
        .routes(routes!(set_slot_expiry))
}

/// Erasure, apart from [`subjects`] because it needs its own capability.
pub(crate) fn erasure() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(erase_subject))
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

/// Every control-plane route group with the capability that guards it. The
/// control surface and its API document are both built from this list, so a
/// route can't be served without being documented.
// r[impl item.api.document]
pub(crate) fn groups() -> Vec<(OpenApiRouter<AppState>, &'static str)> {
    use crate::{
        control_authz, explain_api, import_api, invites, metadata_api, oidc_clients_api,
        registered_scopes_api, shares_api,
    };
    vec![
        (control_authz::tenancy(), capabilities::TENANTS),
        (subjects(), capabilities::SUBJECTS),
        (erasure(), capabilities::SUBJECTS_ERASE),
        (sessions(), capabilities::SESSIONS),
        (signing_keys(), capabilities::KEYS),
        (control_authz::authz(), capabilities::AUTHZ),
        (explain_api::explain(), capabilities::AUTHZ),
        (shares_api::shares(), capabilities::AUTHZ),
        (
            registered_scopes_api::registered_scopes(),
            capabilities::SCOPES_REGISTER,
        ),
        (invites::invites(), capabilities::INVITES),
        (oidc_clients_api::oidc_clients(), capabilities::CLIENTS),
        (import_api::import(), capabilities::IMPORT),
        (metadata_api::subjects(), capabilities::SUBJECTS),
        (metadata_api::tenancy(), capabilities::TENANTS),
        (metadata_api::authz(), capabilities::AUTHZ),
        (metadata_api::invites(), capabilities::INVITES),
        (metadata_api::clients(), capabilities::CLIENTS),
    ]
}

/// The control surface's `/v1` routes, each group behind its guard, and
/// the batch route, which runs its operations through the others.
pub fn routes(state: &AppState) -> Router<AppState> {
    let routes = groups()
        .into_iter()
        .fold(Router::new(), |all, (group, capability)| {
            let (router, _) = group
                .route_layer(guard(state, Some(capability)))
                .split_for_parts();
            all.merge(router)
        });
    let dispatch = batch_api::Dispatch(batch_api::dispatch_router(routes.clone(), state));
    let (batch, _) = batch_api::batch()
        .route_layer(guard(state, None))
        .layer(Extension(dispatch))
        .split_for_parts();
    routes.merge(batch)
}

/// Guards control-plane routes: the bootstrap token (when configured), or an
/// operator's access token whose subject holds `capability` or
/// `konklav:control:all`. Without a capability, any operator passes.
pub(crate) fn guard(state: &AppState, capability: Option<&'static str>) -> GuardLayer {
    middleware::from_fn_with_state(
        (state.clone(), capability),
        check_operator as fn(_, _, _) -> _,
    )
}

type GuardFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;
type GuardState = (AppState, Option<&'static str>);
type GuardLayer = axum::middleware::FromFnLayer<
    fn(State<GuardState>, Request, Next) -> GuardFuture,
    GuardState,
    (State<GuardState>, Request),
>;

// r[impl authz.control-plane.capability]
fn check_operator(
    State((state, capability)): State<GuardState>,
    request: Request,
    next: Next,
) -> GuardFuture {
    Box::pin(async move {
        let mut request = request;
        let db = Db::new(&state, request.extensions());
        match authorize_operator(&state, &db, capability, request.headers()).await {
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
    db: &Db,
    capability: Option<&'static str>,
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
        tracing::info!(?capability, "control plane used with the bootstrap token");
        return Ok(Operator {
            all: true,
            subject: None,
        });
    }
    let mut conn = db.get().await?;
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
    let operator = Operator {
        all,
        subject: Some(session.subject_id),
    };
    let Some(capability) = capability else {
        return Ok(operator);
    };
    if all || capabilities::holds(&mut conn, session.subject_id, capability).await? {
        Ok(operator)
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

/// 201 for a create that created, 200 for an idempotent repeat.
pub(crate) fn created_status(created: bool) -> StatusCode {
    if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    }
}

fn last_cursor(revoked: &[(Session, Cursor)]) -> Option<Cursor> {
    revoked.last().map(|(_, cursor)| *cursor)
}

// --- Subjects ---------------------------------------------------------------

/// Lists subjects.
#[utoipa::path(get, path = "/subjects", tag = "subjects", params(SubjectQuery),
    responses((status = 200, body = SubjectPage)))]
async fn list_subjects(
    db: Db,
    Query(query): Query<SubjectQuery>,
) -> Result<Json<SubjectPage>, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let metadata = metadata::filter(query.metadata.as_deref())?;
    let mut conn = db.get().await?;
    let filter = subjects::SubjectFilter {
        kind: query.kind.map(transport::store_subject_kind),
        identifier: query.identifier.as_deref(),
        metadata: metadata.as_ref(),
    };
    let subjects = subjects::list_by(&mut conn, filter, query.before, limit).await?;
    let next = (i64::try_from(subjects.len()) == Ok(limit))
        .then(|| subjects.last().map(|s| s.id))
        .flatten();
    Ok(Json(SubjectPage {
        subjects: subjects.iter().map(transport::subject).collect(),
        next,
    }))
}

/// Creates a subject.
///
/// Idempotent on the caller-chosen id: repeating the request with the same
/// content returns 200.
#[utoipa::path(put, path = "/subjects/{id}", tag = "subjects",
    params(("id" = SubjectId, Path, description = "Chosen by the caller")),
    request_body = CreateSubject,
    responses(
        (status = 201, description = "Created", body = api::Subject),
        (status = 200, description = "Already existed with the same kind", body = api::Subject),
    ))]
async fn create_subject(
    db: Db,
    limit: metadata::Limit,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CreateSubject>,
) -> Result<Response, ApiError> {
    let id = parse_id(&id, "subject id")?;
    limit.check(&body.metadata)?;
    let mut conn = db.get().await?;
    let kind = transport::store_subject_kind(body.kind);
    let (subject, created) =
        subjects::create_with_metadata(&mut conn, id, kind, &body.metadata).await?;
    let status = created_status(created);
    Ok((status, Json(transport::subject(&subject))).into_response())
}

/// Gets a subject.
#[utoipa::path(get, path = "/subjects/{id}", tag = "subjects", params(("id" = SubjectId, Path)),
    responses((status = 200, body = SubjectDetail)))]
async fn get_subject(db: Db, Path(id): Path<String>) -> Result<Json<SubjectDetail>, ApiError> {
    let id = parse_id(&id, "subject id")?;
    let mut conn = db.get().await?;
    let subject = subjects::get(&mut conn, id)
        .await
        .map_err(|_| ApiError::not_found("subject"))?;
    let credentials = credentials::list_for_subject(&mut conn, id).await?;
    let factors = mfa::list(&mut conn, id).await?;
    Ok(Json(SubjectDetail {
        subject: transport::subject(&subject),
        credentials: credentials.into_iter().map(transport::credential).collect(),
        mfa_factors: factors.iter().map(transport::mfa_factor).collect(),
    }))
}

/// Gets the personal data report of a subject.
///
/// Everything Konklav holds about the subject: its credentials with their
/// login identifiers, MFA factors, memberships with their facts, role
/// assignments, and the sessions, challenges and login attempts not yet
/// deleted by retention. It never holds a hash, a seed, key material or
/// challenge material. For an erased subject every list is empty.
///
/// The report covers Konklav only, not what relying systems hold.
// r[impl subject.report.contents]
// r[impl subject.report.no-secrets]
#[utoipa::path(get, path = "/subjects/{id}/personal-data", tag = "subjects", params(("id" = SubjectId, Path)),
    responses((status = 200, body = PersonalDataReport)))]
async fn personal_data(
    db: Db,
    Path(id): Path<String>,
) -> Result<Json<PersonalDataReport>, ApiError> {
    let id = parse_id(&id, "subject id")?;
    let mut conn = db.get().await?;
    // One snapshot, so the lists agree with each other.
    let held = conn
        .build_transaction()
        .repeatable_read()
        .read_only()
        .run::<_, StoreError, _>(async |conn| personal_data::of(conn, id).await)
        .await
        .map_err(|error| match error {
            StoreError::NotFound => ApiError::not_found("subject"),
            other => other.into(),
        })?;
    Ok(Json(transport::personal_data_report(held)))
}

async fn set_subject_state(
    db: &Db,
    operator: Operator,
    id: &str,
    target: SubjectState,
) -> Result<Json<Written<api::Subject>>, ApiError> {
    let id = parse_id(id, "subject id")?;
    let mut conn = db.get().await?;
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

/// Disables a subject.
///
/// The subject's sessions end.
#[utoipa::path(post, path = "/subjects/{id}/disable", tag = "subjects", params(("id" = SubjectId, Path)),
    responses((status = 200, body = Written<api::Subject>)))]
async fn disable_subject(
    db: Db,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
) -> Result<Json<Written<api::Subject>>, ApiError> {
    set_subject_state(&db, operator, &id, SubjectState::Disabled).await
}

/// Enables a disabled subject.
#[utoipa::path(post, path = "/subjects/{id}/enable", tag = "subjects", params(("id" = SubjectId, Path)),
    responses((status = 200, body = Written<api::Subject>)))]
async fn enable_subject(
    db: Db,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
) -> Result<Json<Written<api::Subject>>, ApiError> {
    set_subject_state(&db, operator, &id, SubjectState::Active).await
}

/// Erases a subject.
///
/// Removes all personal data Konklav holds about the subject, for good: its
/// credentials, MFA factors, challenges, role assignments and membership
/// facts, in history and stored events too. Its sessions and memberships
/// end. The subject stays, as `erased`, and its id is never used again.
/// Relying systems learn of it from a `subject.erased` event.
///
/// Erasing an erased subject changes nothing and returns it without a
/// cursor. A service principal that an OIDC client authenticates as can't
/// be erased until the client is disabled.
// r[impl subject.erasure.operation]
#[utoipa::path(post, path = "/subjects/{id}/erase", tag = "subjects", params(("id" = SubjectId, Path)),
    responses(
        (status = 200, body = Written<api::Subject>),
        (status = 409, description = "An OIDC client authenticates as the subject", body = api::ErrorResponse),
    ))]
async fn erase_subject(
    db: Db,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
) -> Result<Json<Written<api::Subject>>, ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    if operator.subject == Some(id) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "an operator can't erase their own subject",
        ));
    }
    let mut conn = db.get().await?;
    operator.may_change(&mut conn, id).await?;
    let erasure = subjects::erase(&mut conn, id)
        .await
        .map_err(|error| match error {
            StoreError::NotFound => ApiError::not_found("subject"),
            other => other.into(),
        })?;
    Ok(Json(Written {
        value: transport::subject(&erasure.subject),
        cursor: erasure.cursor,
    }))
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

/// Creates a credential for a subject.
///
/// Generated secrets are shown only once. Idempotent on a caller-chosen `id`:
/// repeating the request with the same content returns 200, and for a secret
/// key generates new secrets for both slots and shows those, so the first
/// ones stop working.
// r[impl credential.secret-key.hashed]
#[utoipa::path(post, path = "/subjects/{id}/credentials", tag = "credentials",
    params(("id" = SubjectId, Path)),
    request_body = CreateCredential,
    responses(
        (status = 201, description = "Created. A secret key's secrets are in `secret_keys`, shown only once.", body = CreatedCredential),
        (status = 200, description = "Already existed with the same content. A secret key's new secrets are in `secret_keys`.", body = CreatedCredential),
    ))]
// r[impl metadata.write.create]
async fn create_credential(
    State(state): State<AppState>,
    db: Db,
    limit: metadata::Limit,
    Extension(operator): Extension<Operator>,
    Path(subject_id): Path<String>,
    ApiJson(body): ApiJson<CreateCredential>,
) -> Result<(StatusCode, Json<CreatedCredential>), ApiError> {
    let subject_id: SubjectId = parse_id(&subject_id, "subject id")?;
    let metadata = limit.checked(credential_metadata(&body))?;
    let mut conn = db.get().await?;
    let subject = subjects::get(&mut conn, subject_id)
        .await
        .map_err(|_| ApiError::not_found("subject"))?;
    operator.may_change(&mut conn, subject_id).await?;
    // r[impl platform.idempotency.client-ids]
    if let Some(id) = requested_id(&body)
        && let Ok(existing) = credentials::get(&mut conn, id).await
    {
        return repeat_credential(&state, &mut conn, subject_id, existing, body).await;
    }

    let is_email = matches!(body, CreateCredential::EmailLink { .. });
    let (new, secret_keys) = match body {
        CreateCredential::Password {
            id,
            identifier,
            password,
            password_hash,
            mfa_factors_required,
            ..
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
                metadata: konklav_store::metadata::empty(),
            };
            (new, None)
        }
        CreateCredential::EmailLink { id, identifier, .. }
        | CreateCredential::PhoneOtp { id, identifier, .. } => (
            passwordless_credential(&subject, id, identifier, is_email)?,
            None,
        ),
        CreateCredential::SecretKey { id, expires_at, .. } => {
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
                metadata: konklav_store::metadata::empty(),
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
            ..
        } => (
            workload_credential(&state, &subject, id, provider, upstream)?,
            None,
        ),
    };
    let credential = credentials::insert(&mut conn, NewCredential { metadata, ..new }).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedCredential {
            credential: transport::credential(credential),
            secret_keys,
        }),
    ))
}

fn credential_metadata(body: &CreateCredential) -> &serde_json::Value {
    match body {
        CreateCredential::Password { metadata, .. }
        | CreateCredential::SecretKey { metadata, .. }
        | CreateCredential::EmailLink { metadata, .. }
        | CreateCredential::PhoneOtp { metadata, .. }
        | CreateCredential::Federated { metadata, .. } => metadata,
    }
}

fn requested_id(body: &CreateCredential) -> Option<CredentialId> {
    match body {
        CreateCredential::Password { id, .. }
        | CreateCredential::SecretKey { id, .. }
        | CreateCredential::EmailLink { id, .. }
        | CreateCredential::PhoneOtp { id, .. }
        | CreateCredential::Federated { id, .. } => *id,
    }
}

/// Answers a repeated create of `existing`: 200 with the credential when
/// the request matches it, with new secrets for a secret key, or a
/// conflict.
async fn repeat_credential(
    state: &AppState,
    conn: &mut konklav_store::Connection,
    subject_id: SubjectId,
    existing: Credential,
    body: CreateCredential,
) -> Result<(StatusCode, Json<CreatedCredential>), ApiError> {
    let id = existing.id;
    let conflict = || {
        ApiError::new(
            ErrorCode::Conflict,
            format!("credential {id} already exists with other content"),
        )
    };
    if existing.subject_id != subject_id
        || existing.replaces.is_some()
        || existing.metadata != *credential_metadata(&body)
    {
        return Err(conflict());
    }
    if !existing.is_active() {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            format!("credential {id} was revoked"),
        ));
    }
    let same = match (body, &existing.data) {
        (
            CreateCredential::Password {
                identifier,
                password,
                password_hash,
                mfa_factors_required,
                ..
            },
            CredentialData::Password(data),
        ) => {
            existing.identifier == credentials::normalize_identifier(&identifier)
                && existing.mfa_factors_required == mfa_factors_required
                && match (password, password_hash) {
                    (Some(password), None) => {
                        let hash = data.hash.clone();
                        let check = state
                            .auth
                            .hashing(move |hasher| hasher.verify(&password, &hash))
                            .await?;
                        matches!(check, PasswordCheck::Match { .. })
                    }
                    (None, Some(given)) => given.trim() == data.hash,
                    _ => false,
                }
        }
        (CreateCredential::EmailLink { identifier, .. }, CredentialData::EmailLink)
        | (CreateCredential::PhoneOtp { identifier, .. }, CredentialData::PhoneOtp) => {
            existing.identifier == credentials::normalize_identifier(&identifier)
        }
        (
            CreateCredential::Federated {
                provider,
                subject: upstream,
                ..
            },
            CredentialData::Federated(_),
        ) => {
            existing.identifier
                == credentials::normalize_identifier(&credentials::federated_identifier(
                    &provider, &upstream,
                ))
        }
        (CreateCredential::SecretKey { expires_at, .. }, CredentialData::SecretKey(data)) => {
            if data.a.expires_at != expires_at || data.b.expires_at != expires_at {
                return Err(conflict());
            }
            // The first answer's secrets were shown once and aren't kept.
            let (secret_a, a) = new_slot(state, expires_at).await?;
            let (secret_b, b) = new_slot(state, expires_at).await?;
            credentials::set_data(conn, id, &CredentialData::SecretKey(SecretKeyData { a, b }))
                .await?;
            let credential = credentials::get(conn, id).await?;
            return Ok((
                StatusCode::OK,
                Json(CreatedCredential {
                    credential: transport::credential(credential),
                    secret_keys: Some(SecretKeys {
                        a: format!("{id}.{secret_a}"),
                        b: format!("{id}.{secret_b}"),
                    }),
                }),
            ));
        }
        _ => false,
    };
    if !same {
        return Err(conflict());
    }
    Ok((
        StatusCode::OK,
        Json(CreatedCredential {
            credential: transport::credential(existing),
            secret_keys: None,
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
        metadata: konklav_store::metadata::empty(),
    })
}

/// Revokes a credential.
///
/// Sessions established with the credential end.
// r[impl credential.revocation-ends-sessions]
#[utoipa::path(post, path = "/credentials/{id}/revoke", tag = "credentials",
    params(("id" = CredentialId, Path)),
    request_body(content = Option<RevokeCredential>, description = "Optional"),
    responses((status = 200, body = Written<api::Credential>)))]
async fn revoke_credential(
    db: Db,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    body: Option<ApiJson<RevokeCredential>>,
) -> Result<Json<Written<api::Credential>>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let reason = body
        .and_then(|ApiJson(body)| body.reason)
        .unwrap_or_else(|| "revoked".to_owned());
    let mut conn = db.get().await?;
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

/// Replaces a password.
///
/// Creates a new password credential that records the one it replaces. Sessions
/// established with the old one end. Idempotent on a caller-chosen `id`:
/// repeating the request with the same password returns 200.
#[utoipa::path(post, path = "/credentials/{id}/replace", tag = "credentials",
    params(("id" = CredentialId, Path, description = "The password to replace")),
    request_body = ReplacePassword,
    responses(
        (status = 201, description = "The new password credential", body = Written<api::Credential>),
        (status = 200, description = "Already replaced by this credential with the same password", body = Written<api::Credential>),
    ))]
async fn replace_password(
    State(state): State<AppState>,
    db: Db,
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
    let mut conn = db.get().await?;
    // Outside the transaction: entitlement compilation opens its own.
    if let Ok(old) = credentials::get(&mut conn, old_id).await {
        operator.may_change(&mut conn, old.subject_id).await?;
    }
    // r[impl platform.idempotency.client-ids]
    if let Some(new_id) = body.id
        && let Ok(existing) = credentials::get(&mut conn, new_id).await
    {
        let same = match &existing.data {
            CredentialData::Password(data)
                if existing.replaces == Some(old_id) && existing.is_active() =>
            {
                let (password, hash) = (body.password, data.hash.clone());
                let check = state
                    .auth
                    .hashing(move |hasher| hasher.verify(&password, &hash))
                    .await?;
                matches!(check, PasswordCheck::Match { .. })
            }
            _ => false,
        };
        if !same {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!("credential {new_id} already exists with other content"),
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(Written {
                value: transport::credential(existing),
                cursor: None,
            }),
        ));
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
                    // r[impl metadata.write.create]
                    metadata: old.metadata.clone(),
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

/// Rotates one slot of a secret key.
///
/// Sets a new secret for the slot. The other slot keeps working, so clients can
/// switch over without downtime. The new secret is shown only once.
#[utoipa::path(post, path = "/credentials/{id}/slots/{slot}/rotate", tag = "credentials",
    params(("id" = CredentialId, Path), ("slot" = api::SecretSlot, Path)),
    request_body(content = Option<RotateSlot>, description = "Optional; without it the new secret never expires"),
    responses((status = 200, description = "Rotated. The slot's new secret is in `secret_key`, shown only once.", body = RotatedSlot)))]
async fn rotate_secret_slot(
    State(state): State<AppState>,
    db: Db,
    Path((id, slot)): Path<(String, String)>,
    body: Option<ApiJson<RotateSlot>>,
) -> Result<Json<RotatedSlot>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let slot = parse_slot(&slot)?;
    let expires_at = body.and_then(|ApiJson(body)| body.expires_at);
    let (secret, slot_data) = new_slot(&state, expires_at).await?;
    let mut conn = db.get().await?;
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

/// Sets when one slot of a secret key expires.
///
/// The slot keeps its secret; `null` makes it never expire. An expiry in the
/// past makes the slot's secret stop working at once.
// r[impl credential.secret-key.expiry]
#[utoipa::path(put, path = "/credentials/{id}/slots/{slot}/expiry", tag = "credentials",
    params(("id" = CredentialId, Path), ("slot" = api::SecretSlot, Path)),
    request_body = SlotExpiry,
    responses((status = 200, body = api::Credential)))]
async fn set_slot_expiry(
    db: Db,
    Extension(operator): Extension<Operator>,
    Path((id, slot)): Path<(String, String)>,
    ApiJson(body): ApiJson<SlotExpiry>,
) -> Result<Json<api::Credential>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let slot = parse_slot(&slot)?;
    let mut conn = db.get().await?;
    let credential = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let credential = credentials::get_for_update(conn, id)
                .await
                .map_err(|_| ApiError::not_found("credential"))?;
            operator.may_change(conn, credential.subject_id).await?;
            let CredentialData::SecretKey(mut data) = credential.data.clone() else {
                return Err(ApiError::invalid_request("only secret keys have slots"));
            };
            if !credential.is_active() {
                return Err(ApiError::invalid_request("the credential is revoked"));
            }
            let mut slot_data = data.slot(slot).clone();
            slot_data.expires_at = body.expires_at;
            data.set(slot, slot_data);
            credentials::set_data(conn, id, &CredentialData::SecretKey(data)).await?;
            Ok(credentials::get(conn, id).await?)
        })
        .await?;
    Ok(Json(transport::credential(credential)))
}

fn parse_slot(slot: &str) -> Result<SecretSlot, ApiError> {
    match slot {
        "a" => Ok(SecretSlot::A),
        "b" => Ok(SecretSlot::B),
        _ => Err(ApiError::invalid_request("slot must be a or b")),
    }
}

// --- Sessions ---------------------------------------------------------------

/// Lists sessions.
// r[impl session.admin]
#[utoipa::path(get, path = "/sessions", tag = "sessions", params(SessionQuery),
    responses((status = 200, body = SessionPage)))]
async fn list_sessions(
    db: Db,
    Query(query): Query<SessionQuery>,
) -> Result<Json<SessionPage>, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let filter = SessionFilter {
        subject: query.subject,
        credential: query.credential,
        ..Default::default()
    };
    let mut conn = db.get().await?;
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

/// Gets a session.
#[utoipa::path(get, path = "/sessions/{id}", tag = "sessions", params(("id" = SessionId, Path)),
    responses((status = 200, body = api::Session)))]
async fn get_session(db: Db, Path(id): Path<String>) -> Result<Json<api::Session>, ApiError> {
    let id = parse_id(&id, "session id")?;
    let mut conn = db.get().await?;
    Ok(Json(transport::session(
        sessions::get(&mut conn, id)
            .await
            .map_err(|_| ApiError::not_found("session"))?,
    )))
}

/// Revokes the sessions matching a filter.
#[utoipa::path(post, path = "/sessions/revoke", tag = "sessions",
    request_body = RevokeSessions,
    responses((status = 200, body = Written<RevokedSessions>)))]
async fn revoke_sessions(
    db: Db,
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
    let mut conn = db.get().await?;
    let revoked = sessions::revoke(&mut conn, &filter, body.keep, &reason).await?;
    Ok(Json(Written {
        value: RevokedSessions {
            revoked: revoked.iter().map(|(s, _)| s.id).collect(),
        },
        cursor: last_cursor(&revoked),
    }))
}

// --- Signing keys -----------------------------------------------------------

/// Lists signing keys.
#[utoipa::path(get, path = "/signing-keys", tag = "signing-keys",
    responses((status = 200, body = Vec<api::SigningKey>)))]
async fn list_signing_keys(db: Db) -> Result<Json<Vec<api::SigningKey>>, ApiError> {
    let mut conn = db.get().await?;
    Ok(Json(
        signing_keys::list(&mut conn)
            .await?
            .into_iter()
            .map(transport::signing_key)
            .collect(),
    ))
}

/// Revokes a signing key.
///
/// For break-glass use, when a key is compromised.
#[utoipa::path(post, path = "/signing-keys/{kid}/revoke", tag = "signing-keys",
    params(("kid" = String, Path)),
    responses((status = 200, body = RevokedKey)))]
async fn revoke_signing_key(db: Db, Path(kid): Path<String>) -> Result<Json<RevokedKey>, ApiError> {
    let mut conn = db.get().await?;
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
        metadata: konklav_store::metadata::empty(),
    })
}

/// Sets a credential's session flags.
///
/// Every session started with the credential carries these restrictive flags.
#[utoipa::path(put, path = "/credentials/{id}/session-flags", tag = "credentials",
    params(("id" = CredentialId, Path)),
    request_body = SessionFlags,
    responses((status = 200, body = api::Credential)))]
async fn set_session_flags(
    db: Db,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<SessionFlags>,
) -> Result<Json<api::Credential>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let mut conn = db.get().await?;
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

/// Marks a credential as break-glass.
///
/// Only local passwords and secret keys can be break-glass credentials. Every
/// use of one appends `break_glass.used`.
#[utoipa::path(put, path = "/credentials/{id}/break-glass", tag = "credentials",
    params(("id" = CredentialId, Path)),
    request_body = BreakGlass,
    responses((status = 200, body = api::Credential)))]
async fn set_break_glass(
    db: Db,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<BreakGlass>,
) -> Result<Json<api::Credential>, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let mut conn = db.get().await?;
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
