//! The subject-facing surface: login, refresh and sign-out.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::{Duration, Utc};
use diesel_async::AsyncConnection;
use konklav_authn::{PasswordCheck, RefreshToken};
use konklav_core::{Cursor, SessionId};
use konklav_store::credentials::{self, Credential, CredentialData, CredentialKind};
use konklav_store::sessions::{
    self, ClientKind, NewSession, Rotation, Session, SessionFilter, Stage,
};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::{Connection, catalog, login_attempts, memberships, tenants};
use konklav_token::{AccessClaims, VerifyOptions};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::issue::{self, IssuedToken};
use crate::{AppState, AuthContext, BrowserSettings, keys, pacing};

pub fn routes(state: &AppState) -> Router<AppState> {
    let paced = Router::new()
        .route("/login/password", post(login_password))
        .route("/login/secret-key", post(login_secret_key))
        .route_layer(middleware::from_fn_with_state(state.clone(), pacing::pace));
    Router::new()
        .merge(paced)
        .route("/refresh", post(refresh))
        .route("/login/tenant", post(select_tenant))
        .route("/sign-out", post(sign_out))
        .route("/sign-out/others", post(sign_out_others))
}

const REFRESH_COOKIE: &str = "konklav_refresh";
/// Browser requests to cookie endpoints must carry this header. Setting a
/// custom header forces a CORS preflight, so other sites cannot send it.
const CLIENT_HEADER: &str = "x-konklav-client";
/// Cookies are scoped to the only endpoints that read them.
const COOKIE_PATHS: [&str; 2] = ["/v1/refresh", "/v1/sign-out"];

/// Failed attempts allowed per login identifier, per window.
// r[impl authn.login.rate-limit]
const RATE_LIMITS: [(i64, i64); 3] = [(10 * 60, 30), (60 * 60, 60), (24 * 60 * 60, 120)];

// r[impl session.client-kind]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Client {
    Browser,
    #[default]
    Native,
}

#[derive(Deserialize)]
struct PasswordLogin {
    /// Restrictive session flags the client asks for, from the catalog's
    /// requestable ones.
    #[serde(default)]
    flags: Vec<String>,
    identifier: String,
    password: String,
    #[serde(default)]
    client: Client,
}

#[derive(Deserialize)]
struct SecretKeyLogin {
    key_id: String,
    secret: String,
}

#[derive(Default, Deserialize)]
struct RefreshRequest {
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    #[serde(flatten)]
    token: IssuedToken,
    /// Only for native clients; browser clients get a cookie.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    cursor: Cursor,
}

#[derive(Serialize)]
struct CursorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<Cursor>,
}

fn invalid_credentials() -> ApiError {
    ApiError::new(ErrorCode::InvalidCredentials, "invalid credentials")
}

fn session_ended() -> ApiError {
    ApiError::new(ErrorCode::SessionEnded, "the session has ended")
}

/// Checks that a browser request comes from an allowed origin and carries
/// the client header.
// r[impl session.browser.csrf]
pub(crate) fn check_browser_request<'a>(
    auth: &'a AuthContext,
    headers: &HeaderMap,
) -> Result<&'a BrowserSettings, ApiError> {
    let Some(browser) = &auth.browser else {
        return Err(ApiError::invalid_request("browser clients are not enabled"));
    };
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !origin.is_some_and(|origin| browser.allowed_origins.iter().any(|o| o == origin)) {
        return Err(ApiError::new(ErrorCode::Forbidden, "origin not allowed"));
    }
    if !headers.contains_key(CLIENT_HEADER) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            format!("missing {CLIENT_HEADER} header"),
        ));
    }
    Ok(browser)
}

// r[impl session.browser.cookie]
pub(crate) fn refresh_cookies(
    browser: &BrowserSettings,
    value: &str,
    max_age: i64,
) -> Vec<HeaderValue> {
    let secure = if browser.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    COOKIE_PATHS
        .iter()
        .map(|path| {
            HeaderValue::from_str(&format!(
                "{REFRESH_COOKIE}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Strict{secure}"
            ))
            .expect("cookie header is ASCII")
        })
        .collect()
}

fn read_refresh_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == REFRESH_COOKIE).then(|| value.to_owned())
        })
}

pub(crate) fn with_cookies(mut response: Response, cookies: Vec<HeaderValue>) -> Response {
    for cookie in cookies {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

async fn enforce_rate_limit(
    conn: &mut Connection,
    kind: CredentialKind,
    identifier: &str,
) -> Result<(), ApiError> {
    let now = Utc::now();
    for (window, limit) in RATE_LIMITS {
        let failures =
            login_attempts::failures_since(conn, kind, identifier, now - Duration::seconds(window))
                .await?;
        if failures >= limit {
            return Err(ApiError::new(
                ErrorCode::RateLimited,
                "too many failed attempts; try again later",
            ));
        }
    }
    Ok(())
}

/// Only requestable (restrictive) catalog flags may be asked for at login.
// r[impl session.flags.origin]
async fn check_requested_flags(conn: &mut Connection, flags: &[String]) -> Result<(), ApiError> {
    if flags.is_empty() {
        return Ok(());
    }
    let catalog = catalog::load(conn).await?;
    for flag in flags {
        let requestable = catalog
            .session_flags
            .iter()
            .any(|entry| entry.name == *flag && entry.requestable);
        if !requestable {
            return Err(ApiError::invalid_request(format!(
                "session flag `{flag}` cannot be requested"
            )));
        }
    }
    Ok(())
}

/// Starts a session after a successful first factor and issues its first
/// tokens.
/// A new session's refresh token and the change-feed cursor of its event.
pub(crate) struct Started {
    pub session: Session,
    pub refresh: RefreshToken,
    pub cursor: Cursor,
}

/// Starts a session for `credential`, at most `lifetime` long.
pub(crate) async fn create_session(
    state: &AppState,
    conn: &mut Connection,
    credential: &Credential,
    amr: Vec<String>,
    client: Client,
    flags: &[String],
    lifetime: chrono::Duration,
) -> Result<Started, ApiError> {
    let now = Utc::now();
    let id = SessionId::new_v7();
    let refresh = RefreshToken::generate(id);
    // r[impl credential.mfa-requirement]
    let stage = if credential.mfa_factors_required > 0 {
        Stage::Partial
    } else {
        Stage::Identity
    };
    let new = NewSession {
        id,
        subject_id: credential.subject_id,
        credential_id: credential.id,
        stage,
        client_kind: match client {
            Client::Browser => ClientKind::Browser,
            Client::Native => ClientKind::Native,
        },
        amr,
        auth_time: now,
        flags: flags.to_vec(),
        impersonator_subject_id: None,
        parent_session_id: None,
        refresh_hash: refresh.hash(),
        expires_at: now + lifetime.min(state.auth.session_lifetime),
    };
    let (session, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let (session, cursor) = sessions::insert(conn, new).await?;
            if !credential.break_glass {
                return Ok((session, cursor));
            }
            // r[impl federation.break-glass]
            let cursor = konklav_store::events::append(
                conn,
                "break_glass.used",
                serde_json::json!({
                    "subject": session.subject_id,
                    "credential": credential.id,
                    "kind": credential.kind().as_str(),
                    "session": session.id,
                }),
            )
            .await?;
            tracing::warn!(subject = %session.subject_id, credential = %credential.id, "break-glass credential used");
            Ok((session, cursor))
        })
        .await?;
    Ok(Started {
        session,
        refresh,
        cursor,
    })
}

async fn start_session(
    state: &AppState,
    conn: &mut Connection,
    credential: &Credential,
    amr: &str,
    client: Client,
    browser: Option<&BrowserSettings>,
    flags: &[String],
) -> Result<Response, ApiError> {
    let now = Utc::now();
    let Started {
        session,
        refresh,
        cursor,
    } = create_session(
        state,
        conn,
        credential,
        vec![amr.to_owned()],
        client,
        flags,
        state.auth.session_lifetime,
    )
    .await?;
    let stage = session.stage;
    let token = issue::access_token(conn, &state.auth, &session).await?;

    // A partial session can only complete MFA, so it gets no refresh token.
    let refreshable = stage != Stage::Partial;
    let (refresh_token, cookies) = match (client, browser) {
        (Client::Browser, Some(browser)) if refreshable => (
            None,
            refresh_cookies(
                browser,
                refresh.as_str(),
                (session.expires_at - now).num_seconds(),
            ),
        ),
        (Client::Native, _) if refreshable => (Some(refresh.as_str().to_owned()), Vec::new()),
        _ => (None, Vec::new()),
    };
    let body = TokenResponse {
        token,
        refresh_token,
        cursor,
    };
    Ok(with_cookies(Json(body).into_response(), cookies))
}

/// `POST /v1/login/password`
// r[impl authn.login.methods]
async fn login_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PasswordLogin>,
) -> Result<Response, ApiError> {
    let browser = match body.client {
        Client::Browser => Some(check_browser_request(&state.auth, &headers)?.clone()),
        Client::Native => None,
    };
    let mut conn = state.pool.get().await?;
    check_requested_flags(&mut conn, &body.flags).await?;
    let kind = CredentialKind::Password;
    enforce_rate_limit(&mut conn, kind, &body.identifier).await?;

    let credential = credentials::find_active(&mut conn, kind, &body.identifier).await?;
    let subject = match &credential {
        Some(credential) => Some(subjects::get(&mut conn, credential.subject_id).await?),
        None => None,
    };
    let hash = match &credential {
        Some(Credential {
            data: CredentialData::Password(data),
            ..
        }) => Some(data.hash.clone()),
        _ => None,
    };
    let hasher = state.auth.hasher.clone();
    let password = body.password.clone();
    let check = tokio::task::spawn_blocking(move || match hash {
        Some(hash) => hasher.verify(&password, &hash),
        None => {
            hasher.verify_dummy(&password);
            PasswordCheck::Mismatch
        }
    })
    .await
    .map_err(ApiError::internal)?;

    // Passwords are interactive, so service principals can't use them.
    let usable = subject
        .as_ref()
        .is_some_and(|s| s.state == SubjectState::Active && s.kind == SubjectKind::Human);
    let succeeded = usable && matches!(check, PasswordCheck::Match { .. });
    login_attempts::record(&mut conn, kind, &body.identifier, succeeded).await?;
    // r[impl platform.error.no-enumeration]
    let (Some(credential), true) = (credential, succeeded) else {
        return Err(invalid_credentials());
    };

    if check == (PasswordCheck::Match { needs_rehash: true }) {
        let hasher = state.auth.hasher.clone();
        let password = body.password;
        let hash = tokio::task::spawn_blocking(move || hasher.hash(&password))
            .await
            .map_err(ApiError::internal)?;
        let data = CredentialData::Password(credentials::PasswordData { hash });
        credentials::set_data(&mut conn, credential.id, &data).await?;
    }

    start_session(
        &state,
        &mut conn,
        &credential,
        "pwd",
        body.client,
        browser.as_ref(),
        &body.flags,
    )
    .await
}

/// `POST /v1/login/secret-key`: service principals exchange a secret key
/// for tokens. Native clients only.
async fn login_secret_key(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<SecretKeyLogin>,
) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let kind = CredentialKind::SecretKey;
    enforce_rate_limit(&mut conn, kind, &body.key_id).await?;

    let credential = credentials::find_active(&mut conn, kind, &body.key_id).await?;
    let subject = match &credential {
        Some(credential) => Some(subjects::get(&mut conn, credential.subject_id).await?),
        None => None,
    };
    let now = Utc::now();
    let hashes = match &credential {
        Some(Credential {
            data: CredentialData::SecretKey(data),
            ..
        }) => data
            .slots()
            .into_iter()
            .map(|(_, slot)| slot)
            .filter(|slot| slot.expires_at.is_none_or(|expires| expires > now))
            .map(|slot| slot.hash.clone())
            .collect(),
        _ => Vec::new(),
    };
    let hasher = state.auth.hasher.clone();
    let secret = body.secret.clone();
    let matched = tokio::task::spawn_blocking(move || {
        if hashes.is_empty() {
            hasher.verify_dummy(&secret);
            return false;
        }
        // Check every slot so the time taken doesn't reveal which matched.
        hashes
            .iter()
            .map(|hash| matches!(hasher.verify(&secret, hash), PasswordCheck::Match { .. }))
            .fold(false, |any, matched| any | matched)
    })
    .await
    .map_err(ApiError::internal)?;

    // r[impl subject.kind]
    let usable = subject
        .as_ref()
        .is_some_and(|s| s.state == SubjectState::Active && s.kind == SubjectKind::Service);
    let succeeded = usable && matched;
    login_attempts::record(&mut conn, kind, &body.key_id, succeeded).await?;
    let (Some(credential), true) = (credential, succeeded) else {
        return Err(invalid_credentials());
    };
    start_session(
        &state,
        &mut conn,
        &credential,
        "swk",
        Client::Native,
        None,
        &[],
    )
    .await
}

/// Ends `session` if its subject or credential is no longer usable.
// r[impl session.refresh.recompute]
pub(crate) async fn still_valid(
    conn: &mut Connection,
    session: &Session,
) -> Result<bool, ApiError> {
    let subject = subjects::get(conn, session.subject_id).await?;
    let credential = credentials::get(conn, session.credential_id).await?;
    if subject.state == SubjectState::Active && credential.is_active() {
        return Ok(true);
    }
    let filter = SessionFilter {
        session: Some(session.id),
        ..Default::default()
    };
    sessions::revoke(conn, &filter, None, "no_longer_valid").await?;
    Ok(false)
}

/// Rotates a refresh token, checking that its session is still usable and,
/// when `client` is given, that it belongs to that OIDC client.
pub(crate) async fn rotate(
    conn: &mut Connection,
    presented: &str,
    client: Option<&str>,
) -> Result<Started, ApiError> {
    let presented = RefreshToken::parse(presented).map_err(|_| session_ended())?;
    let current = sessions::get(conn, presented.session())
        .await
        .map_err(|_| session_ended())?;
    if current.stage == Stage::Partial
        || current.oidc_client_id.as_deref() != client
        || !still_valid(conn, &current).await?
    {
        return Err(session_ended());
    }
    let next = RefreshToken::generate(presented.session());
    let rotation = sessions::rotate_refresh(
        conn,
        presented.session(),
        &presented.hash(),
        &next.hash(),
        Utc::now(),
    )
    .await?;
    match rotation {
        Rotation::Rotated(session, cursor) => Ok(Started {
            session,
            refresh: next,
            cursor,
        }),
        Rotation::Reused(session, _) => {
            tracing::warn!(session = %session.id, "refresh token reused; session revoked");
            Err(session_ended())
        }
        Rotation::Ended(_) | Rotation::Invalid => Err(session_ended()),
    }
}

/// `POST /v1/refresh`: native clients send `refresh_token` in the body;
/// browsers send the cookie.
async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<ApiJson<RefreshRequest>>,
) -> Result<Response, ApiError> {
    let body = body.map(|ApiJson(body)| body).unwrap_or_default();
    let (presented, browser) = match body.refresh_token {
        Some(token) => (token, None),
        None => {
            let browser = check_browser_request(&state.auth, &headers)?.clone();
            let token = read_refresh_cookie(&headers)
                .ok_or_else(|| ApiError::new(ErrorCode::Unauthenticated, "no refresh token"))?;
            (token, Some(browser))
        }
    };
    let mut conn = state.pool.get().await?;
    let Started {
        session,
        refresh: next,
        cursor,
    } = rotate(&mut conn, &presented, None).await?;
    let token = issue::access_token(&mut conn, &state.auth, &session).await?;
    let now = Utc::now();
    let (refresh_token, cookies) = match &browser {
        Some(browser) => (
            None,
            refresh_cookies(
                browser,
                next.as_str(),
                (session.expires_at - now).num_seconds(),
            ),
        ),
        None => (Some(next.as_str().to_owned()), Vec::new()),
    };
    let body = TokenResponse {
        token,
        refresh_token,
        cursor,
    };
    Ok(with_cookies(Json(body).into_response(), cookies))
}

/// Verifies a bearer access token and its session: the session must be
/// active and the token issued at its current version.
// r[impl session.version]
pub(crate) async fn authenticate(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
) -> Result<(AccessClaims, Session), ApiError> {
    let unauthenticated = || {
        ApiError::new(
            ErrorCode::Unauthenticated,
            "missing or invalid access token",
        )
    };
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(unauthenticated)?;
    verify_access_token(state, conn, token).await
}

/// Verifies an access token and its session: the session must be active
/// and the token issued at its current version.
pub(crate) async fn verify_access_token(
    state: &AppState,
    conn: &mut Connection,
    token: &str,
) -> Result<(AccessClaims, Session), ApiError> {
    verify_access_token_for(state, conn, token, &state.auth.audience).await
}

/// [`verify_access_token`] for tokens with another audience, such as those
/// issued to an OIDC client.
pub(crate) async fn verify_access_token_for(
    state: &AppState,
    conn: &mut Connection,
    token: &str,
    audience: &str,
) -> Result<(AccessClaims, Session), ApiError> {
    let unauthenticated = || {
        ApiError::new(
            ErrorCode::Unauthenticated,
            "missing or invalid access token",
        )
    };
    let kid = konklav_token::decode_unverified_kid(token).map_err(|_| unauthenticated())?;
    let key = keys::verifying_key(conn, &kid, state.auth.access_ttl).await?;
    let options = VerifyOptions {
        issuer: &state.auth.issuer,
        audience,
        now: Utc::now().timestamp(),
        leeway: 30,
    };
    let claims = konklav_token::verify(token, |_| key, &options).map_err(|_| unauthenticated())?;
    let session = sessions::get(conn, claims.sid)
        .await
        .map_err(|_| session_ended())?;
    if !session.is_active_at(Utc::now()) || claims.sv < session.version {
        return Err(session_ended());
    }
    Ok((claims, session))
}

/// `POST /v1/sign-out`: ends the caller's session, identified by a bearer
/// access token or, for browsers, the refresh cookie.
async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let mut conn = state.pool.get().await?;
    let (session_id, browser) = if headers.contains_key(header::AUTHORIZATION) {
        let (claims, _) = authenticate(&state, &mut conn, &headers).await?;
        (claims.sid, state.auth.browser.clone())
    } else {
        let browser = check_browser_request(&state.auth, &headers)?.clone();
        let presented = read_refresh_cookie(&headers)
            .and_then(|token| RefreshToken::parse(&token).ok())
            .ok_or_else(|| ApiError::new(ErrorCode::Unauthenticated, "no refresh token"))?;
        // Only the current refresh token may sign out; anything else is a
        // stale or forged cookie, which still gets cleared below.
        if !sessions::refresh_matches(&mut conn, presented.session(), &presented.hash()).await? {
            return Ok(clear_cookies(
                Some(&browser),
                CursorResponse { cursor: None },
            ));
        }
        (presented.session(), Some(browser))
    };
    let filter = SessionFilter {
        session: Some(session_id),
        ..Default::default()
    };
    let revoked = sessions::revoke(&mut conn, &filter, None, "signed_out").await?;
    let cursor = revoked.last().map(|(_, cursor)| *cursor);
    Ok(clear_cookies(browser.as_ref(), CursorResponse { cursor }))
}

fn clear_cookies(browser: Option<&BrowserSettings>, body: CursorResponse) -> Response {
    let cookies = browser
        .map(|b| refresh_cookies(b, "", 0))
        .unwrap_or_default();
    with_cookies(Json(body).into_response(), cookies)
}

/// `POST /v1/sign-out/others`: ends every other session of the caller's
/// subject.
async fn sign_out_others(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CursorResponse>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (claims, _) = authenticate(&state, &mut conn, &headers).await?;
    let filter = SessionFilter {
        subject: Some(claims.sub),
        ..Default::default()
    };
    let revoked =
        sessions::revoke(&mut conn, &filter, Some(claims.sid), "signed_out_elsewhere").await?;
    Ok(Json(CursorResponse {
        cursor: revoked.last().map(|(_, cursor)| *cursor),
    }))
}

#[derive(Deserialize)]
struct SelectTenant {
    /// A tenant id, or `root`.
    tenant: String,
}

/// `POST /v1/login/tenant`: moves the caller's session into a tenant where
/// the subject has an active membership, and issues a tenant token.
// r[impl authn.login.tenant-selection]
async fn select_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<SelectTenant>,
) -> Result<Json<TokenResponse>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (claims, session) = authenticate(&state, &mut conn, &headers).await?;
    if session.stage == Stage::Partial {
        return Err(ApiError::new(ErrorCode::Forbidden, "complete MFA first"));
    }
    let tenant_id = tenants::parse_reference(&body.tenant)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))?;
    let no_access = || ApiError::new(ErrorCode::Forbidden, "no active membership in that tenant");
    let tenant = tenants::get(&mut conn, tenant_id)
        .await
        .map_err(|_| no_access())?;
    if tenant.state != tenants::TenantState::Active {
        return Err(no_access());
    }
    let membership = memberships::find_active(&mut conn, claims.sub, tenant_id)
        .await?
        .ok_or_else(no_access)?;
    let (session, cursor) =
        sessions::select_tenant(&mut conn, session.id, tenant_id, membership.id).await?;
    let token = issue::access_token(&mut conn, &state.auth, &session).await?;
    Ok(Json(TokenResponse {
        token,
        refresh_token: None,
        cursor,
    }))
}

/// Starts a native session after a passwordless first factor (magic link,
/// phone code, invite), checking the subject can still log in.
pub(crate) async fn start_passwordless_session(
    state: &AppState,
    conn: &mut Connection,
    credential: &Credential,
    amr: &str,
) -> Result<Response, ApiError> {
    let subject = subjects::get(conn, credential.subject_id).await?;
    if subject.state != SubjectState::Active
        || subject.kind != SubjectKind::Human
        || !credential.is_active()
    {
        return Err(invalid_credentials());
    }
    start_session(state, conn, credential, amr, Client::Native, None, &[]).await
}
