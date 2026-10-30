//! Subject-facing flows beyond password login: MFA enrollment and
//! verification, step-up, passwordless login (magic links, phone codes),
//! password reset and change, and impersonation.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use diesel_async::AsyncConnection;
use konklav_authn::{
    PasswordCheck, RefreshToken, TotpSecret, generate_code, generate_secret, hash_challenge_secret,
    verify_totp,
};
use konklav_core::{CredentialId, Cursor, SessionId, SubjectId};
use konklav_store::challenges::{self, NewChallenge, Purpose};
use konklav_store::credentials::{
    self, Credential, CredentialData, CredentialKind, NewCredential, PasswordData,
};
use konklav_store::mfa::{self, EmailCodeData, Factor, FactorData, FactorKind, TotpData};
use konklav_store::sessions::{self, ClientKind, NewSession, Session, SessionFilter, Stage};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::{Connection, events, login_attempts, memberships, tenants};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::client_address::ClientAddress;
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::issue::{self, IssuedToken};
use crate::subject_api::{
    authenticate, begin_attempt, check_browser_request, refresh_cookies, refuse_impersonation,
    require_recent, start_passwordless_session, with_cookies,
};
use crate::{AppState, capabilities, pacing, passkeys_api};

pub fn routes(state: &AppState) -> Router<AppState> {
    let paced = Router::new()
        .route("/login/mfa", post(complete_mfa))
        .route("/step-up", post(step_up))
        .route("/login/email-link/start", post(start_email_link))
        .route("/login/email-link/complete", post(complete_email_link))
        .route("/login/phone/start", post(start_phone))
        .route("/login/phone/complete", post(complete_phone))
        .route("/password-reset/start", post(start_reset))
        .route("/password-reset/complete", post(complete_reset))
        .route("/password/change", post(change_password))
        .route_layer(middleware::from_fn_with_state(state.clone(), pacing::pace));
    Router::new()
        .merge(paced)
        .route("/mfa", get(list_factors))
        .route("/mfa/totp", post(enroll_totp))
        .route("/mfa/email", post(enroll_email))
        .route("/mfa/{id}/activate", post(activate_factor))
        .route("/mfa/{id}/send", post(send_factor_code))
        .route("/mfa/{id}", delete(remove_factor))
        .route("/impersonate", post(impersonate))
}

const CODE_TTL_MINUTES: i64 = 10;
const LINK_TTL_MINUTES: i64 = 15;
/// Challenges sent per recipient and purpose, per window in seconds. The
/// daily cap bounds how many codes can be guessed against: each allows a
/// few attempts.
pub(crate) const SEND_LIMITS: [(i64, i64); 2] = [(10 * 60, 5), (24 * 60 * 60, 20)];
const IMPERSONATION_MINUTES: i64 = 60;
/// Failed TOTP checks allowed per factor, per window in seconds.
pub(crate) const TOTP_LIMITS: [(i64, i64); 2] = [(10 * 60, 5), (24 * 60 * 60, 20)];

fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(serde_json::json!({}))).into_response()
}

/// Treats a send refused by the rate limit as done. Starts for unknown
/// identifiers send nothing and are always accepted, so refusing a known
/// one would reveal that it exists.
// r[impl platform.error.no-enumeration]
fn quietly_limited(error: ApiError) -> Result<(), ApiError> {
    if error.code == ErrorCode::RateLimited {
        Ok(())
    } else {
        Err(error)
    }
}

fn invalid_code() -> ApiError {
    ApiError::new(ErrorCode::InvalidCredentials, "invalid or expired code")
}

/// Emits a `delivery.requested` event; the relying system sends it.
// r[impl challenge.delivery.event]
async fn request_delivery(
    conn: &mut Connection,
    channel: &str,
    recipient: &str,
    purpose: &str,
    subject: Option<SubjectId>,
    material: serde_json::Value,
    expires_at: chrono::DateTime<Utc>,
) -> Result<Cursor, ApiError> {
    Ok(events::append(
        conn,
        "delivery.requested",
        serde_json::json!({
            "channel": channel,
            "recipient": recipient,
            "purpose": purpose,
            "subject": subject,
            "material": material,
            "expires_at": expires_at.timestamp(),
        }),
    )
    .await?)
}

/// Creates a challenge and its delivery, unless the recipient has had too
/// many recently. Returns the secret.
#[allow(clippy::too_many_arguments)]
async fn issue_challenge(
    conn: &mut Connection,
    purpose: Purpose,
    channel: &str,
    recipient: &str,
    secret: String,
    ttl: Duration,
    link: Option<&str>,
    fill: impl FnOnce(&mut NewChallenge),
) -> Result<(), ApiError> {
    let now = Utc::now();
    let id = uuid::Uuid::now_v7();
    let mut new = NewChallenge {
        id,
        purpose,
        subject_id: None,
        credential_id: None,
        mfa_factor_id: None,
        session_id: None,
        recipient: recipient.to_owned(),
        secret_hash: hash_challenge_secret(&id.to_string(), &secret),
        details: serde_json::json!({}),
        expires_at: now + ttl,
    };
    fill(&mut new);
    // An MFA factor's address is whatever its subject entered, so other
    // subjects' factors for the same address must not use up its sends.
    let counted = match purpose {
        Purpose::MfaEmailCode => new.subject_id,
        _ => None,
    };
    // r[impl challenge.send-limit]
    for (window, limit) in SEND_LIMITS {
        let since = now - Duration::seconds(window);
        if challenges::count_since(conn, purpose, recipient, counted, since).await? >= limit {
            return Err(ApiError::new(
                ErrorCode::RateLimited,
                "too many requests; try again later",
            ));
        }
    }
    let subject = new.subject_id;
    let expires_at = new.expires_at;
    challenges::create(conn, new).await?;
    let material = match link {
        Some(_) => serde_json::json!({"token": format!("{id}.{secret}")}),
        None => serde_json::json!({"code": secret}),
    };
    request_delivery(
        conn,
        channel,
        recipient,
        purpose.as_str(),
        subject,
        material,
        expires_at,
    )
    .await?;
    Ok(())
}

/// Parses `<challenge id>.<secret>` link tokens.
fn parse_link(token: &str) -> Option<(uuid::Uuid, &str)> {
    let (id, secret) = token.split_once('.')?;
    Some((id.parse().ok()?, secret))
}

/// Verifies a link token for `purpose` and consumes it.
async fn redeem_link(
    conn: &mut Connection,
    purpose: Purpose,
    token: &str,
) -> Result<challenges::Challenge, ApiError> {
    let (id, secret) = parse_link(token).ok_or_else(invalid_code)?;
    let challenge = challenges::get(conn, id)
        .await
        .map_err(|_| invalid_code())?;
    let now = Utc::now();
    let matches: bool = hash_challenge_secret(&id.to_string(), secret)
        .ct_eq(&challenge.secret_hash)
        .into();
    if challenge.purpose != purpose.as_str() || !challenge.is_usable(now) || !matches {
        return Err(invalid_code());
    }
    if !challenges::consume(conn, id, now).await? {
        return Err(invalid_code());
    }
    Ok(challenge)
}

/// Verifies a code for the newest challenge of `purpose` sent to
/// `recipient`, counting the attempt, and consumes it.
async fn redeem_code(
    conn: &mut Connection,
    purpose: Purpose,
    recipient: &str,
    code: &str,
    factor: Option<uuid::Uuid>,
) -> Result<challenges::Challenge, ApiError> {
    let now = Utc::now();
    // r[impl authn.mfa.factor-codes]
    let challenge = challenges::latest(conn, purpose, recipient, factor, now)
        .await?
        .ok_or_else(invalid_code)?;
    let challenge = challenges::record_attempt(conn, challenge.id).await?;
    let matches: bool = hash_challenge_secret(&challenge.id.to_string(), code)
        .ct_eq(&challenge.secret_hash)
        .into();
    if !challenge.is_usable(now) && challenge.attempts > challenge.max_attempts {
        return Err(invalid_code());
    }
    if !matches
        || challenge.attempts > challenge.max_attempts
        || !challenges::consume(conn, challenge.id, now).await?
    {
        return Err(invalid_code());
    }
    Ok(challenge)
}

// --- MFA ----------------------------------------------------------------------

#[derive(Serialize)]
struct FactorView {
    id: uuid::Uuid,
    kind: FactorKind,
    active: bool,
    created_at: chrono::DateTime<Utc>,
}

impl From<&Factor> for FactorView {
    fn from(factor: &Factor) -> Self {
        Self {
            id: factor.id,
            kind: factor.data.kind(),
            active: factor.active,
            created_at: factor.created_at,
        }
    }
}

/// Authenticates a full (non-partial) session.
async fn full_session(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
) -> Result<Session, ApiError> {
    let (_, session) = authenticate(state, conn, headers).await?;
    if session.stage == Stage::Partial {
        return Err(ApiError::new(ErrorCode::Forbidden, "complete MFA first"));
    }
    Ok(session)
}

/// Authenticates a full session that may change the subject's own
/// authentication: not one started by impersonation.
async fn own_session(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
) -> Result<Session, ApiError> {
    let session = full_session(state, conn, headers).await?;
    refuse_impersonation(&session)?;
    Ok(session)
}

/// [`own_session`] that authenticated recently, for changing factors.
// r[impl authn.mfa.management]
async fn recent_own_session(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
) -> Result<Session, ApiError> {
    let session = own_session(state, conn, headers).await?;
    require_recent(&session)?;
    Ok(session)
}

/// `GET /v1/mfa`: the subject's factors. A partial session sees only the
/// active ones, to pick one for completing login.
// r[impl authn.mfa.partial-factors]
async fn list_factors(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<FactorView>>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (_, session) = authenticate(&state, &mut conn, &headers).await?;
    let partial = session.stage == Stage::Partial;
    let factors = mfa::list(&mut conn, session.subject_id).await?;
    Ok(Json(
        factors
            .iter()
            .filter(|factor| !partial || factor.active)
            .map(FactorView::from)
            .collect(),
    ))
}

#[derive(Serialize)]
struct TotpEnrollment {
    factor_id: uuid::Uuid,
    /// Base32 seed, shown once.
    secret: String,
    uri: String,
}

/// `POST /v1/mfa/totp`: registers an inactive TOTP factor.
async fn enroll_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TotpEnrollment>, ApiError> {
    let mut conn = state.pool.get().await?;
    let session = recent_own_session(&state, &mut conn, &headers).await?;
    let seed = TotpSecret::generate();
    let sealed = state
        .auth
        .secrets
        .encrypt(seed.as_bytes())
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    let factor = mfa::create(
        &mut conn,
        session.subject_id,
        &FactorData::Totp(TotpData {
            key_id: sealed.key_id,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            last_step: None,
        }),
    )
    .await?;
    Ok(Json(TotpEnrollment {
        factor_id: factor.id,
        uri: seed.uri(&state.auth.issuer, &session.subject_id.to_string()),
        secret: seed.to_base32(),
    }))
}

#[derive(Deserialize)]
struct EmailFactor {
    email: String,
}

/// `POST /v1/mfa/email`: registers an inactive email-code factor and sends a
/// code to activate it.
async fn enroll_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<EmailFactor>,
) -> Result<(StatusCode, Json<FactorView>), ApiError> {
    if !body.email.contains('@') {
        return Err(ApiError::invalid_request("email must be an email address"));
    }
    let mut conn = state.pool.get().await?;
    let session = recent_own_session(&state, &mut conn, &headers).await?;
    let factor = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let factor = mfa::create(
                conn,
                session.subject_id,
                &FactorData::EmailCode(EmailCodeData {
                    email: body.email.clone(),
                }),
            )
            .await?;
            send_email_code(conn, &factor).await?;
            Ok(factor)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(FactorView::from(&factor))))
}

async fn send_email_code(conn: &mut Connection, factor: &Factor) -> Result<(), ApiError> {
    let FactorData::EmailCode(data) = &factor.data else {
        return Err(ApiError::invalid_request(
            "only email factors are sent codes",
        ));
    };
    let subject = factor.subject_id;
    let id = factor.id;
    issue_challenge(
        conn,
        Purpose::MfaEmailCode,
        "email",
        &data.email,
        generate_code(6),
        Duration::minutes(CODE_TTL_MINUTES),
        None,
        |new| {
            new.subject_id = Some(subject);
            new.mfa_factor_id = Some(id);
        },
    )
    .await
}

/// Checks a code against a factor, returning the `amr` value it proves.
async fn verify_factor(
    state: &AppState,
    conn: &mut Connection,
    factor: &Factor,
    code: &str,
) -> Result<&'static str, ApiError> {
    match &factor.data {
        FactorData::Totp(_) => {
            // The outcome is returned rather than raised, so that a failed
            // check is committed and counts.
            let outcome = conn
                .transaction::<_, ApiError, _>(async |conn| {
                    verify_totp_locked(state, conn, factor.id, code).await
                })
                .await?;
            outcome.map(|()| "otp")
        }
        FactorData::EmailCode(data) => {
            redeem_code(
                conn,
                Purpose::MfaEmailCode,
                &data.email,
                code,
                Some(factor.id),
            )
            .await?;
            Ok("eml")
        }
    }
}

/// Checks a TOTP code under a lock on its factor, so concurrent checks can
/// neither exceed the attempt limit nor accept one code twice. The outer
/// result is for database errors, the inner one for the check.
// r[impl authn.mfa.attempts]
async fn verify_totp_locked(
    state: &AppState,
    conn: &mut Connection,
    id: uuid::Uuid,
    code: &str,
) -> Result<Result<(), ApiError>, ApiError> {
    let factor = mfa::lock(conn, id).await?;
    let FactorData::Totp(data) = &factor.data else {
        return Ok(Err(invalid_code()));
    };
    let now = Utc::now();
    for (window, limit) in TOTP_LIMITS {
        let failures =
            login_attempts::totp_failures_since(conn, id, now - Duration::seconds(window)).await?;
        if failures >= limit {
            return Ok(Err(ApiError::new(
                ErrorCode::RateLimited,
                "too many failed codes; try again later",
            )));
        }
    }
    let seed = state
        .auth
        .secrets
        .decrypt(&konklav_authn::EncryptedSecret {
            key_id: data.key_id.clone(),
            nonce: data.nonce.clone(),
            ciphertext: data.ciphertext.clone(),
        })
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    let step = verify_totp(
        &TotpSecret::from_bytes(seed),
        code,
        now.timestamp(),
        data.last_step,
    );
    login_attempts::record_totp(conn, id, step.is_some()).await?;
    let Some(step) = step else {
        return Ok(Err(invalid_code()));
    };
    let mut updated = data.clone();
    updated.last_step = Some(step);
    mfa::set_data(conn, id, &FactorData::Totp(updated)).await?;
    Ok(Ok(()))
}

#[derive(Deserialize)]
struct Code {
    code: String,
}

/// `POST /v1/mfa/{id}/activate`
async fn activate_factor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    ApiJson(body): ApiJson<Code>,
) -> Result<Json<FactorView>, ApiError> {
    let mut conn = state.pool.get().await?;
    let session = recent_own_session(&state, &mut conn, &headers).await?;
    let factor = mfa::get(&mut conn, session.subject_id, id)
        .await
        .map_err(|_| ApiError::not_found("factor"))?;
    verify_factor(&state, &mut conn, &factor, &body.code).await?;
    mfa::activate(&mut conn, id).await?;
    let factor = mfa::get(&mut conn, session.subject_id, id).await?;
    Ok(Json(FactorView::from(&factor)))
}

/// `POST /v1/mfa/{id}/send`: sends a code for an email factor, during login
/// (partial session) or step-up.
async fn send_factor_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let (_, session) = authenticate(&state, &mut conn, &headers).await?;
    let factor = mfa::get(&mut conn, session.subject_id, id)
        .await
        .map_err(|_| ApiError::not_found("factor"))?;
    conn.transaction::<_, ApiError, _>(async |conn| send_email_code(conn, &factor).await)
        .await?;
    Ok(accepted())
}

async fn remove_factor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.pool.get().await?;
    let session = recent_own_session(&state, &mut conn, &headers).await?;
    let removed = mfa::remove(&mut conn, session.subject_id, id).await?;
    Ok(Json(serde_json::json!({"removed": removed})))
}

#[derive(Deserialize)]
struct FactorCode {
    factor_id: uuid::Uuid,
    code: String,
}

#[derive(Serialize)]
struct TokenBody {
    #[serde(flatten)]
    token: IssuedToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    cursor: Cursor,
}

/// `POST /v1/login/mfa`: proves one factor in a partial session. Once the
/// credential's required number of factors is proven, the session becomes
/// an identity session and gets its refresh token.
async fn complete_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<FactorCode>,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let (_, session) = authenticate(&state, &mut conn, &headers).await?;
    if session.stage != Stage::Partial {
        return Err(ApiError::invalid_request("the session has no pending MFA"));
    }
    // r[impl session.browser.mfa]
    let browser = match session.client_kind {
        ClientKind::Browser => Some(check_browser_request(&state.auth, &headers)?.clone()),
        ClientKind::Native => None,
    };
    let factor = mfa::get(&mut conn, session.subject_id, body.factor_id)
        .await
        .ok()
        .filter(|f| f.active)
        .ok_or_else(invalid_code)?;
    let amr = verify_factor(&state, &mut conn, &factor, &body.code).await?;
    let credential = credentials::get(&mut conn, session.credential_id).await?;
    let required = usize::try_from(credential.mfa_factors_required)
        .unwrap_or(1)
        .max(1);
    let refresh = RefreshToken::generate(session.id);
    let (session, cursor) = sessions::verify_mfa_factor(
        &mut conn,
        session.id,
        &factor.id.to_string(),
        amr,
        required,
        &refresh.hash(),
    )
    .await?;
    let token = issue::access_token(&mut conn, &state.auth, &session).await?;
    // Once MFA is done, browsers get the refresh token as a cookie and
    // native clients in the body.
    let done = session.stage != Stage::Partial;
    let (refresh_token, cookies) = match &browser {
        Some(browser) if done => (
            None,
            refresh_cookies(
                browser,
                refresh.as_str(),
                (session.expires_at - Utc::now()).num_seconds(),
            ),
        ),
        None if done => (Some(refresh.as_str().to_owned()), Vec::new()),
        _ => (None, Vec::new()),
    };
    let body = TokenBody {
        token,
        refresh_token,
        cursor,
    };
    Ok(with_cookies(Json(body).into_response(), cookies))
}

#[derive(Deserialize)]
struct StepUpRequest {
    factor_id: Option<uuid::Uuid>,
    code: Option<String>,
    password: Option<String>,
    /// From `POST /v1/step-up/passkey/options`, with `passkey`.
    ceremony: Option<String>,
    passkey: Option<webauthn_rs::prelude::PublicKeyCredential>,
}

/// `POST /v1/step-up`: proves a factor, the password or a passkey again
/// within the current session, refreshing its authentication time.
async fn step_up(
    State(state): State<AppState>,
    address: ClientAddress,
    headers: HeaderMap,
    ApiJson(body): ApiJson<StepUpRequest>,
) -> Result<Json<TokenBody>, ApiError> {
    let mut conn = state.pool.get().await?;
    let session = full_session(&state, &mut conn, &headers).await?;
    let passkey = body.ceremony.zip(body.passkey);
    let amr: Vec<&str> = match (body.factor_id, body.code, body.password, passkey) {
        (Some(factor_id), Some(code), None, None) => {
            let factor = mfa::get(&mut conn, session.subject_id, factor_id)
                .await
                .ok()
                .filter(|f| f.active)
                .ok_or_else(invalid_code)?;
            vec![verify_factor(&state, &mut conn, &factor, &code).await?]
        }
        (None, None, Some(password), None) => {
            verify_password_of(&state, &mut conn, session.subject_id, &password, address).await?;
            vec!["pwd"]
        }
        (None, None, None, Some((ceremony, passkey))) => {
            passkeys_api::verify_step_up(&state, &mut conn, &session, &ceremony, &passkey).await?;
            passkeys_api::PASSKEY_AMR.to_vec()
        }
        _ => {
            return Err(ApiError::invalid_request(
                "give either factor_id and code, password, or ceremony and passkey",
            ));
        }
    };
    let (session, cursor) = sessions::step_up(&mut conn, session.id, &amr).await?;
    let token = issue::access_token(&mut conn, &state.auth, &session).await?;
    Ok(Json(TokenBody {
        token,
        refresh_token: None,
        cursor,
    }))
}

/// The subject's active password credential, if `password` matches it.
async fn verify_password_of(
    state: &AppState,
    conn: &mut Connection,
    subject: SubjectId,
    password: &str,
    address: ClientAddress,
) -> Result<Credential, ApiError> {
    let credential = credentials::list_for_subject(conn, subject)
        .await?
        .into_iter()
        .find(|c| c.is_active() && c.kind() == CredentialKind::Password)
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidCredentials, "invalid credentials"))?;
    let CredentialData::Password(data) = &credential.data else {
        unreachable!("filtered to passwords")
    };
    // Counts toward the login limit, so step-up and password change can't
    // be used to guess the password instead.
    let attempt = begin_attempt(
        conn,
        CredentialKind::Password,
        &credential.identifier,
        address,
    )
    .await?;
    let (password, hash) = (password.to_owned(), data.hash.clone());
    let check = state
        .auth
        .hashing(move |hasher| hasher.verify(&password, &hash))
        .await?;
    let matched = matches!(check, PasswordCheck::Match { .. });
    attempt.finish(conn, matched).await?;
    if matched {
        Ok(credential)
    } else {
        Err(ApiError::new(
            ErrorCode::InvalidCredentials,
            "invalid credentials",
        ))
    }
}

// --- Passwordless login -------------------------------------------------------

#[derive(Deserialize)]
struct StartEmailLink {
    email: String,
}

/// `POST /v1/login/email-link/start`: always accepted, so the response
/// reveals nothing about which addresses exist.
async fn start_email_link(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<StartEmailLink>,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let Some(credential) =
        credentials::find_active(&mut conn, CredentialKind::EmailLink, &body.email).await?
    else {
        return Ok(accepted());
    };
    conn.transaction::<_, ApiError, _>(async |conn| {
        issue_challenge(
            conn,
            Purpose::EmailLink,
            "email",
            &credential.identifier,
            generate_secret(),
            Duration::minutes(LINK_TTL_MINUTES),
            Some("link"),
            |new| {
                new.subject_id = Some(credential.subject_id);
                new.credential_id = Some(credential.id);
            },
        )
        .await
    })
    .await
    .or_else(quietly_limited)?;
    Ok(accepted())
}

#[derive(Deserialize)]
struct CompleteLink {
    token: String,
}

async fn complete_email_link(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<CompleteLink>,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let challenge = redeem_link(&mut conn, Purpose::EmailLink, &body.token).await?;
    let credential = challenge.credential_id.ok_or_else(invalid_code)?;
    let credential = credentials::get(&mut conn, credential).await?;
    start_passwordless_session(&state, &mut conn, &credential, "eml").await
}

#[derive(Deserialize)]
struct StartPhone {
    phone: String,
}

async fn start_phone(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<StartPhone>,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let Some(credential) =
        credentials::find_active(&mut conn, CredentialKind::PhoneOtp, &body.phone).await?
    else {
        return Ok(accepted());
    };
    conn.transaction::<_, ApiError, _>(async |conn| {
        issue_challenge(
            conn,
            Purpose::PhoneCode,
            "sms",
            &credential.identifier,
            generate_code(6),
            Duration::minutes(CODE_TTL_MINUTES),
            None,
            |new| {
                new.subject_id = Some(credential.subject_id);
                new.credential_id = Some(credential.id);
            },
        )
        .await
    })
    .await
    .or_else(quietly_limited)?;
    Ok(accepted())
}

#[derive(Deserialize)]
struct CompletePhone {
    phone: String,
    code: String,
}

async fn complete_phone(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<CompletePhone>,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let recipient = credentials::normalize_identifier(&body.phone);
    let challenge =
        redeem_code(&mut conn, Purpose::PhoneCode, &recipient, &body.code, None).await?;
    let credential =
        credentials::get(&mut conn, challenge.credential_id.ok_or_else(invalid_code)?).await?;
    start_passwordless_session(&state, &mut conn, &credential, "sms").await
}

// --- Passwords ------------------------------------------------------------------

#[derive(Deserialize)]
struct StartReset {
    identifier: String,
}

/// `POST /v1/password-reset/start`: always accepted.
async fn start_reset(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<StartReset>,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let Some(credential) =
        credentials::find_active(&mut conn, CredentialKind::Password, &body.identifier).await?
    else {
        return Ok(accepted());
    };
    conn.transaction::<_, ApiError, _>(async |conn| {
        issue_challenge(
            conn,
            Purpose::ResetPassword,
            "email",
            &credential.identifier,
            generate_secret(),
            Duration::minutes(LINK_TTL_MINUTES),
            Some("link"),
            |new| {
                new.subject_id = Some(credential.subject_id);
                new.credential_id = Some(credential.id);
            },
        )
        .await
    })
    .await
    .or_else(quietly_limited)?;
    Ok(accepted())
}

const MIN_PASSWORD_LENGTH: usize = 8;

fn check_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ApiError::invalid_request(format!(
            "passwords need at least {MIN_PASSWORD_LENGTH} characters"
        )));
    }
    Ok(())
}

/// Replaces a password credential with a new one holding `hash`.
async fn replace_password(
    conn: &mut Connection,
    old: &Credential,
    hash: String,
) -> Result<Credential, ApiError> {
    credentials::revoke(conn, old.id, "replaced").await?;
    Ok(credentials::insert(
        conn,
        NewCredential {
            id: CredentialId::new_v7(),
            subject_id: old.subject_id,
            identifier: old.identifier.clone(),
            data: CredentialData::Password(PasswordData { hash }),
            mfa_factors_required: old.mfa_factors_required,
            replaces: Some(old.id),
        },
    )
    .await?)
}

#[derive(Deserialize)]
struct CompleteReset {
    token: String,
    password: String,
}

/// `POST /v1/password-reset/complete`: sets a new password and ends every
/// session of the subject.
// r[impl authn.reset-password]
async fn complete_reset(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<CompleteReset>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_password(&body.password)?;
    let password = body.password.clone();
    let hash = state
        .auth
        .hashing(move |hasher| hasher.hash(&password))
        .await?;
    let mut conn = state.pool.get().await?;
    let cursor = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let challenge = redeem_link(conn, Purpose::ResetPassword, &body.token).await?;
            let old =
                credentials::get(conn, challenge.credential_id.ok_or_else(invalid_code)?).await?;
            if !old.is_active() {
                return Err(invalid_code());
            }
            replace_password(conn, &old, hash).await?;
            let filter = SessionFilter {
                subject: Some(old.subject_id),
                ..Default::default()
            };
            sessions::revoke(conn, &filter, None, "password_reset").await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await?;
    Ok(Json(serde_json::json!({"cursor": cursor})))
}

#[derive(Deserialize)]
struct ChangePassword {
    current: String,
    new: String,
}

/// `POST /v1/password/change`: keeps the caller's session, ends the others.
async fn change_password(
    State(state): State<AppState>,
    address: ClientAddress,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ChangePassword>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_password(&body.new)?;
    let mut conn = state.pool.get().await?;
    let session = own_session(&state, &mut conn, &headers).await?;
    let old = verify_password_of(
        &state,
        &mut conn,
        session.subject_id,
        &body.current,
        address,
    )
    .await?;
    let password = body.new.clone();
    let hash = state
        .auth
        .hashing(move |hasher| hasher.hash(&password))
        .await?;
    let cursor = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let new = replace_password(conn, &old, hash).await?;
            sessions::move_to_credential(conn, session.id, new.id).await?;
            let filter = SessionFilter {
                subject: Some(session.subject_id),
                ..Default::default()
            };
            sessions::revoke(conn, &filter, Some(session.id), "password_changed").await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await?;
    Ok(Json(serde_json::json!({"cursor": cursor})))
}

// --- Impersonation --------------------------------------------------------------

#[derive(Deserialize)]
struct Impersonate {
    subject: SubjectId,
    /// Optionally start directly in one of the target's tenants.
    tenant: Option<String>,
}

/// `POST /v1/impersonate`: starts a time-bounded session as another subject.
/// Its tokens carry the caller in `act`, and it ends with the caller's
/// session.
// r[impl authn.impersonation.actor-chain]
async fn impersonate(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Impersonate>,
) -> Result<Json<TokenBody>, ApiError> {
    let mut conn = state.pool.get().await?;
    let parent = own_session(&state, &mut conn, &headers).await?;
    capabilities::require(&mut conn, parent.subject_id, capabilities::IMPERSONATE).await?;
    let target = subjects::get(&mut conn, body.subject)
        .await
        .map_err(|_| ApiError::not_found("subject"))?;
    if target.state != SubjectState::Active
        || target.kind != SubjectKind::Human
        || target.id == parent.subject_id
    {
        return Err(ApiError::invalid_request(
            "only other active people can be impersonated",
        ));
    }
    let membership = match body.tenant.as_deref() {
        Some(reference) => {
            let tenant = tenants::parse_reference(reference)
                .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))?;
            Some(
                memberships::find_active(&mut conn, target.id, tenant)
                    .await?
                    .ok_or_else(|| {
                        ApiError::new(ErrorCode::Forbidden, "no active membership in that tenant")
                    })?,
            )
        }
        None => None,
    };
    let now = Utc::now();
    let id = SessionId::new_v7();
    let (session, _) = sessions::insert(
        &mut conn,
        NewSession {
            id,
            subject_id: target.id,
            // The impersonator's credential: the target's credentials were
            // never presented.
            credential_id: parent.credential_id,
            stage: Stage::Identity,
            client_kind: parent.client_kind,
            amr: parent.amr.clone(),
            auth_time: parent.auth_time,
            flags: Vec::new(),
            impersonator_subject_id: Some(parent.subject_id),
            parent_session_id: Some(parent.id),
            refresh_hash: RefreshToken::generate(id).hash(),
            expires_at: (now + Duration::minutes(IMPERSONATION_MINUTES)).min(parent.expires_at),
        },
    )
    .await?;
    let (session, cursor) = match membership {
        Some(membership) => {
            sessions::select_tenant(&mut conn, session.id, membership.tenant_id, membership.id)
                .await?
        }
        None => {
            let cursor = events::head(&mut conn).await?;
            (session, cursor)
        }
    };
    let token = issue::access_token(&mut conn, &state.auth, &session).await?;
    Ok(Json(TokenBody {
        token,
        refresh_token: None,
        cursor,
    }))
}
