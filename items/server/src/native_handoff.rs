//! Login requests, of both kinds, and the native login hand-off.
//!
//! A login request is started either by an OIDC client
//! (`GET /v1/oauth2/authorize`, in [`crate::oidc_api`]) or by a native app on
//! the subject's computer, such as the operator CLI. Login applications
//! answer both at the same neutral paths:
//!
//! - `GET /v1/login-requests/{id}` says which kind it is and what it needs
//! - `POST /v1/login-requests/{id}/accept` and `…/reject` answer it, and
//!   return where to send the browser
//!
//! The paths under `/v1/oauth2/login-requests/` are kept as deprecated
//! aliases.
//!
//! The native hand-off:
//!
//! 1. The app opens `GET /v1/login-requests/native/authorize` with a
//!    loopback redirect URI, a PKCE challenge, a DPoP key thumbprint, a
//!    `state` and its name. Konklav keeps the request, binds it to the
//!    browser with a cookie, and redirects to the login URL.
//! 2. The login application signs the subject in, asks them to confirm,
//!    and accepts the request.
//! 3. `GET /v1/login-requests/native/resume` checks the browser is the one
//!    that started and was answered, and redirects to the loopback URI with
//!    a single-use code.
//! 4. The app exchanges the code at `POST /v1/login-requests/native/token`
//!    with the PKCE verifier and a proof made with the named key, for a new
//!    bound session of its own.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use diesel_async::AsyncConnection;
use konklav_authn::{RefreshToken, generate_secret, hash_challenge_secret};
use konklav_core::{Cursor, SessionId, TenantId};
use konklav_store::challenges::{self, Challenge, NewChallenge, Purpose};
use konklav_store::sessions::{self, ClientKind, NewSession, Session, Stage};
use konklav_store::{Connection, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{BrowserConfig, Tokens};
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::issue::{self, IssuedToken};
use crate::oidc_api::{
    self, Accepted, CODE_SECONDS, LOGIN_REQUEST_MINUTES, REFUSALS, Refusal, ResumeQuery,
};
use crate::{AppState, dpop, pacing, subject_api};

/// The app name a hand-off may give when none are configured.
pub const DEFAULT_APP: &str = "konklav-cli";

/// The native login hand-off's settings, built once at startup.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Where hand-offs send people to sign in.
    pub login_url: String,
    /// The app names a hand-off may give.
    pub apps: Vec<String>,
    /// A native session's absolute lifetime.
    pub session_lifetime: Duration,
}

impl Settings {
    /// The hand-off's settings, when it is configured and on. `login_page`
    /// is the built-in login page's URL when it is served, and
    /// `provider_login_url` the OpenID provider's configured login URL.
    ///
    /// # Errors
    ///
    /// When it is on without browser sign-in or a login URL, or with a
    /// lifetime longer than the instance's session lifetime.
    // r[impl session.native-handoff.disabled]
    pub fn configure(
        tokens: &Tokens,
        browser: &BrowserConfig,
        login_page: Option<&str>,
        provider_login_url: Option<&str>,
    ) -> Result<Option<Self>, String> {
        let Some(config) = browser.native_handoff.as_ref().filter(|c| c.enabled) else {
            return Ok(None);
        };
        if browser.browser.is_none() {
            return Err(
                "native_handoff needs browser sign-in for its login application: configure \
                 `browser`"
                    .into(),
            );
        }
        let login_url = config
            .login_url
            .as_deref()
            .or(login_page)
            .or(provider_login_url)
            .ok_or(
                "native_handoff needs a login URL: set native_handoff.login_url or turn on \
                 login_page",
            )?
            .to_owned();
        if config.session_lifetime_seconds == 0
            || config.session_lifetime_seconds > tokens.session_lifetime_seconds
        {
            return Err(format!(
                "native_handoff.session_lifetime_seconds must be between 1 and \
                 tokens.session_lifetime_seconds ({})",
                tokens.session_lifetime_seconds
            ));
        }
        let apps = if config.apps.is_empty() {
            vec![DEFAULT_APP.to_owned()]
        } else {
            config.apps.clone()
        };
        if let Some(app) = apps.iter().find(|app| !is_app_name(app)) {
            return Err(format!(
                "native_handoff.apps: {app:?} isn't 1 to 64 lowercase letters, digits or -"
            ));
        }
        Ok(Some(Self {
            login_url,
            apps,
            session_lifetime: Duration::seconds(i64::from(config.session_lifetime_seconds)),
        }))
    }
}

fn is_app_name(app: &str) -> bool {
    (1..=64).contains(&app.len())
        && app
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn routes(state: &AppState) -> Router<AppState> {
    let paced = Router::new()
        .route("/login-requests/native/token", post(token))
        .route_layer(middleware::from_fn_with_state(state.clone(), pacing::pace));
    Router::new()
        .route("/login-requests/native/authorize", get(authorize))
        .route("/login-requests/native/resume", get(resume))
        // r[impl session.login-requests.paths]
        .route("/login-requests/{id}", get(login_request))
        .route("/login-requests/{id}/accept", post(accept))
        .route("/login-requests/{id}/reject", post(reject))
        // Deprecated aliases, until the next major version.
        .route("/oauth2/login-requests/{id}", get(login_request))
        .route("/oauth2/login-requests/{id}/accept", post(accept))
        .route("/oauth2/login-requests/{id}/reject", post(reject))
        .merge(paced)
}

fn settings(state: &AppState) -> Result<&Settings, ApiError> {
    state
        .auth
        .native_handoff
        .as_ref()
        .ok_or_else(|| ApiError::not_found("native login hand-off"))
}

fn endpoint(state: &AppState, path: &str) -> String {
    format!(
        "{}/v1/login-requests/native/{path}",
        state.auth.issuer.trim_end_matches('/')
    )
}

// --- Both kinds ------------------------------------------------------------

/// Whether `id` names a native login request; anything else is left to the
/// OpenID provider, which answers 404 for what it doesn't know either.
async fn is_native(state: &AppState, id: &str) -> Result<bool, ApiError> {
    let Ok(id) = id.parse::<uuid::Uuid>() else {
        return Ok(false);
    };
    let mut conn = state.pool.get().await?;
    Ok(match challenges::get(&mut conn, id).await {
        Ok(challenge) => challenge.purpose == Purpose::NativeAuthorize.as_str(),
        Err(StoreError::NotFound) => false,
        Err(error) => return Err(error.into()),
    })
}

/// `GET /v1/login-requests/{id}`
async fn login_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    if !is_native(&state, &id).await? {
        return oidc_api::login_request(State(state), Path(id))
            .await
            .map(IntoResponse::into_response);
    }
    settings(&state)?;
    let mut conn = state.pool.get().await?;
    let (_, details) = pending_request(&mut conn, &id).await?;
    Ok(Json(NativeView {
        kind: "native",
        app: details.app,
    })
    .into_response())
}

/// `POST /v1/login-requests/{id}/accept`
async fn accept(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Accepted>, ApiError> {
    if !is_native(&state, &id).await? {
        return oidc_api::accept(State(state), Path(id), headers).await;
    }
    accept_native(&state, &id, &headers).await
}

/// `POST /v1/login-requests/{id}/reject`
async fn reject(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(refusal): ApiJson<Refusal>,
) -> Result<Json<Accepted>, ApiError> {
    if !is_native(&state, &id).await? {
        return oidc_api::reject(State(state), Path(id), headers, ApiJson(refusal)).await;
    }
    reject_native(&state, &id, &headers, refusal).await
}

// --- Native requests -----------------------------------------------------

#[derive(Serialize)]
struct NativeView {
    /// `native`: an app on the subject's computer started the request.
    kind: &'static str,
    /// The app's name, which the login application shows when it asks the
    /// subject to confirm.
    app: String,
}

/// A native login request, as kept in its challenge.
#[derive(Clone, Serialize, Deserialize)]
struct RequestDetails {
    app: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    dpop_jkt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acceptance_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refusal: Option<String>,
    /// The tenant the accepting session was in when it accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_tenant: Option<TenantId>,
}

/// A native login hand-off's code, as kept in its challenge.
#[derive(Clone, Serialize, Deserialize)]
struct CodeDetails {
    app: String,
    redirect_uri: String,
    code_challenge: String,
    dpop_jkt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<TenantId>,
    /// The session the code was exchanged for, revoked if the code is
    /// presented again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_session: Option<SessionId>,
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    dpop_jkt: Option<String>,
    state: Option<String>,
    app: Option<String>,
}

/// A loopback redirect URI as RFC 8252 section 7.3 describes it, on an IP
/// literal and the path `/callback`, written as the URL parser writes it
/// so that no other spelling of a host can pass.
// r[impl session.native-handoff.redirect]
fn is_loopback_redirect(uri: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(uri) else {
        return false;
    };
    let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]"));
    parsed.scheme() == "http"
        && loopback
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/callback"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.as_str() == uri
}

/// `GET /v1/login-requests/native/authorize`. Every error is a page in the
/// browser: nothing goes to the redirect URI before the subject agreed.
async fn authorize(
    State(state): State<AppState>,
    query: Result<Query<AuthorizeQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    oidc_api::error_page(match query {
        Ok(Query(query)) => start(&state, query).await,
        Err(rejection) => Err(ApiError::invalid_request(rejection.body_text())),
    })
}

async fn start(state: &AppState, query: AuthorizeQuery) -> Result<Response, ApiError> {
    let settings = settings(state)?;
    let redirect_uri = query
        .redirect_uri
        .filter(|uri| is_loopback_redirect(uri))
        .ok_or_else(|| {
            ApiError::invalid_request(
                "redirect_uri must be http://127.0.0.1:<port>/callback or \
                 http://[::1]:<port>/callback",
            )
        })?;
    let app = query
        .app
        .filter(|app| settings.apps.contains(app))
        .ok_or_else(|| ApiError::invalid_request("app isn't one this server knows"))?;
    // r[impl session.native-handoff.pkce]
    let code_challenge = match (query.code_challenge, query.code_challenge_method.as_deref()) {
        (Some(challenge), Some("S256")) if oidc_api::is_code_challenge(&challenge) => challenge,
        _ => {
            return Err(ApiError::invalid_request(
                "an S256 code_challenge is required",
            ));
        }
    };
    // r[impl session.native-handoff.dpop]
    let dpop_jkt = query
        .dpop_jkt
        .filter(|jkt| oidc_api::is_thumbprint(jkt))
        .ok_or_else(|| ApiError::invalid_request("a dpop_jkt key thumbprint is required"))?;
    let request_state = query
        .state
        .filter(|s| (1..=512).contains(&s.len()))
        .ok_or_else(|| ApiError::invalid_request("a state of up to 512 characters is required"))?;

    let mut conn = state.pool.get().await?;
    let id = uuid::Uuid::now_v7();
    let secret = generate_secret();
    let details = RequestDetails {
        app: app.clone(),
        redirect_uri,
        state: request_state,
        code_challenge,
        dpop_jkt,
        acceptance_hash: None,
        refusal: None,
        accepted_tenant: None,
    };
    challenges::create(
        &mut conn,
        NewChallenge {
            id,
            purpose: Purpose::NativeAuthorize,
            subject_id: None,
            credential_id: None,
            mfa_factor_id: None,
            session_id: None,
            recipient: app,
            secret_hash: hash_challenge_secret(&id.to_string(), &secret),
            details: serde_json::to_value(&details).map_err(ApiError::internal)?,
            expires_at: Utc::now() + Duration::minutes(LOGIN_REQUEST_MINUTES),
        },
    )
    .await?;
    let mut response =
        oidc_api::redirect_to(&settings.login_url, &[("login_request", &id.to_string())]);
    response.headers_mut().append(
        header::SET_COOKIE,
        oidc_api::cookie(state, &format!("{id}.{secret}"), LOGIN_REQUEST_MINUTES * 60),
    );
    Ok(response)
}

async fn pending_request(
    conn: &mut Connection,
    id: &str,
) -> Result<(Challenge, RequestDetails), ApiError> {
    let unknown = || ApiError::not_found("login request");
    let id: uuid::Uuid = id.parse().map_err(|_| unknown())?;
    let challenge = challenges::get(conn, id).await.map_err(|_| unknown())?;
    if challenge.purpose != Purpose::NativeAuthorize.as_str() || !challenge.is_usable(Utc::now()) {
        return Err(unknown());
    }
    let details = serde_json::from_value(challenge.details.clone()).map_err(|_| unknown())?;
    Ok((challenge, details))
}

fn answered() -> ApiError {
    ApiError::new(ErrorCode::Conflict, "the request was already answered")
}

fn resume_url(state: &AppState, id: uuid::Uuid, acceptance: &str) -> String {
    format!(
        "{}?login_request={id}&acceptance={acceptance}",
        endpoint(state, "resume")
    )
}

/// Accepts a native request with the login application's session. The
/// login application has asked the subject to confirm
/// (`r[session.native-handoff.confirm]`).
async fn accept_native(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
) -> Result<Json<Accepted>, ApiError> {
    settings(state)?;
    subject_api::check_browser_request(&state.auth, headers)?;
    let mut conn = state.pool.get().await?;
    let (_, session) = subject_api::authenticate(state, &mut conn, headers).await?;
    let (challenge, mut details) = pending_request(&mut conn, id).await?;
    if details.refusal.is_some() {
        return Err(answered());
    }
    if session.stage == Stage::Partial || session.oidc_client_id.is_some() {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "sign in through the login application first",
        ));
    }
    // An operator acting as someone else can't hand that on to an app.
    subject_api::refuse_impersonation(&session)?;
    details.accepted_tenant = session.tenant_id;
    let acceptance = generate_secret();
    details.acceptance_hash = Some(oidc_api::acceptance_hash(challenge.id, &acceptance));
    let stored = serde_json::to_value(&details).map_err(ApiError::internal)?;
    if !challenges::attach_session(&mut conn, challenge.id, session.id, &stored).await? {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "the request was already accepted",
        ));
    }
    Ok(Json(Accepted {
        redirect_to: resume_url(state, challenge.id, &acceptance),
    }))
}

/// Refuses a native request; the app gets the error at its redirect URI.
async fn reject_native(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
    refusal: Refusal,
) -> Result<Json<Accepted>, ApiError> {
    settings(state)?;
    subject_api::check_browser_request(&state.auth, headers)?;
    if !REFUSALS.contains(&refusal.error.as_str()) {
        return Err(ApiError::invalid_request(format!(
            "error must be one of {}",
            REFUSALS.join(", ")
        )));
    }
    let mut conn = state.pool.get().await?;
    let (challenge, mut details) = pending_request(&mut conn, id).await?;
    if challenge.session_id.is_some() || details.refusal.is_some() {
        return Err(answered());
    }
    let acceptance = generate_secret();
    details.acceptance_hash = Some(oidc_api::acceptance_hash(challenge.id, &acceptance));
    details.refusal = Some(refusal.error);
    let stored = serde_json::to_value(&details).map_err(ApiError::internal)?;
    challenges::set_details(&mut conn, challenge.id, &stored).await?;
    Ok(Json(Accepted {
        redirect_to: resume_url(state, challenge.id, &acceptance),
    }))
}

/// `GET /v1/login-requests/native/resume`
async fn resume(
    State(state): State<AppState>,
    Query(query): Query<ResumeQuery>,
    headers: HeaderMap,
) -> Response {
    oidc_api::error_page(resume_native(&state, &query, &headers).await)
}

// r[impl session.native-handoff.code]
async fn resume_native(
    state: &AppState,
    query: &ResumeQuery,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    settings(state)?;
    let foreign = || ApiError::invalid_request("this browser didn't start the request");
    let mut conn = state.pool.get().await?;
    let (challenge, details) = pending_request(&mut conn, &query.login_request).await?;
    oidc_api::check_resuming_browser(
        state,
        headers,
        &challenge,
        details.acceptance_hash.as_deref(),
        query.acceptance.as_deref(),
    )?;
    let issuer = state.auth.issuer.as_str();
    let mut response = if let Some(error) = &details.refusal {
        if !challenges::consume(&mut conn, challenge.id, Utc::now()).await? {
            return Err(foreign());
        }
        oidc_api::client_error(&details.redirect_uri, error, Some(&details.state), issuer)
    } else {
        let session = challenge
            .session_id
            .ok_or_else(|| ApiError::invalid_request("the request hasn't been accepted"))?;
        if !challenges::consume(&mut conn, challenge.id, Utc::now()).await? {
            return Err(foreign());
        }
        let code_id = uuid::Uuid::now_v7();
        let code_secret = generate_secret();
        challenges::create(
            &mut conn,
            NewChallenge {
                id: code_id,
                purpose: Purpose::NativeCode,
                subject_id: None,
                credential_id: None,
                mfa_factor_id: None,
                session_id: Some(session),
                recipient: details.app.clone(),
                secret_hash: hash_challenge_secret(&code_id.to_string(), &code_secret),
                details: serde_json::to_value(CodeDetails {
                    app: details.app.clone(),
                    redirect_uri: details.redirect_uri.clone(),
                    code_challenge: details.code_challenge.clone(),
                    dpop_jkt: details.dpop_jkt.clone(),
                    tenant: details.accepted_tenant,
                    issued_session: None,
                })
                .map_err(ApiError::internal)?,
                expires_at: Utc::now() + Duration::seconds(CODE_SECONDS),
            },
        )
        .await?;
        let code = format!("{code_id}.{code_secret}");
        oidc_api::redirect_to(
            &details.redirect_uri,
            &[("code", &code), ("state", &details.state), ("iss", issuer)],
        )
    };
    response
        .headers_mut()
        .append(header::SET_COOKIE, oidc_api::cookie(state, "", 0));
    Ok(response)
}

#[derive(Deserialize)]
struct TokenRequest {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(Serialize)]
struct TokenResponse {
    #[serde(flatten)]
    token: IssuedToken,
    refresh_token: String,
    cursor: Cursor,
}

fn refused(message: &str) -> ApiError {
    ApiError::new(ErrorCode::InvalidCredentials, message.to_owned())
}

/// `POST /v1/login-requests/native/token`: the code, its verifier and the
/// redirect URI, with a DPoP proof for this URL made with the request's key.
// r[impl session.native-handoff.dpop]
// r[impl session.native-handoff.pkce]
// r[impl session.native-handoff.session]
async fn token(
    State(state): State<AppState>,
    dpop::Bound(jkt): dpop::Bound,
    ApiJson(body): ApiJson<TokenRequest>,
) -> Result<Response, ApiError> {
    let settings = settings(&state)?;
    let Some(jkt) = jkt else {
        return Ok(dpop::invalid_resource_request(
            "the code exchange needs a DPoP proof",
        ));
    };
    let Some((id, secret)) = body.code.split_once('.') else {
        return Err(refused("malformed code"));
    };
    let Ok(id) = id.parse::<uuid::Uuid>() else {
        return Err(refused("malformed code"));
    };
    let mut conn = state.pool.get().await?;
    let challenge = match challenges::get(&mut conn, id).await {
        Ok(challenge) => challenge,
        Err(StoreError::NotFound) => return Err(refused("unknown code")),
        Err(error) => return Err(error.into()),
    };
    let matches: bool = hash_challenge_secret(&id.to_string(), secret)
        .ct_eq(&challenge.secret_hash)
        .into();
    let Ok(details) = serde_json::from_value::<CodeDetails>(challenge.details.clone()) else {
        return Err(refused("unknown code"));
    };
    if !matches
        || challenge.purpose != Purpose::NativeCode.as_str()
        || body.redirect_uri != details.redirect_uri
    {
        return Err(refused("the code wasn't issued for this redirect URI"));
    }
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(body.code_verifier.as_bytes()));
    if !bool::from(computed.as_bytes().ct_eq(details.code_challenge.as_bytes())) {
        return Err(refused("PKCE verification failed"));
    }
    if jkt != details.dpop_jkt {
        return Ok(dpop::invalid_resource_request(
            "the code is bound to another DPoP key",
        ));
    }
    let lifetime = settings.session_lifetime;
    let outcome = conn
        .transaction::<_, ApiError, _>(async |conn| {
            if !challenges::consume(conn, id, Utc::now()).await? {
                return Ok(Err("the code was used or expired"));
            }
            let Some(accepting) = challenge.session_id else {
                return Ok(Err("unknown code"));
            };
            let accepting = sessions::get(conn, accepting).await?;
            if !accepting.is_active_at(Utc::now())
                || !subject_api::still_valid(conn, &accepting).await?
            {
                return Ok(Err("the sign-in has ended"));
            }
            let tenant = match details.tenant {
                Some(tenant) => {
                    match oidc_api::accepted_membership(conn, &accepting, tenant).await? {
                        Some(membership) => Some((tenant, membership)),
                        None => return Ok(Err("the sign-in's tenant is no longer available")),
                    }
                }
                None => None,
            };
            let started = start_native_session(conn, &accepting, tenant, &jkt, lifetime).await?;
            let issued = CodeDetails {
                issued_session: Some(started.0.id),
                ..details.clone()
            };
            let issued = serde_json::to_value(issued).map_err(ApiError::internal)?;
            challenges::set_details(conn, id, &issued).await?;
            Ok(Ok(started))
        })
        .await?;
    let (session, refresh, cursor) = match outcome {
        Ok(started) => started,
        Err(reason) => {
            revoke_if_reused(&mut conn, id).await?;
            return Err(refused(reason));
        }
    };
    let token = issue::access_token(&mut conn, &state.auth, &session).await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(TokenResponse {
            token,
            refresh_token: refresh.as_str().to_owned(),
            cursor,
        }),
    )
        .into_response())
}

/// Starts the native session: independent of the accepting session, so
/// ending that one leaves it, but no longer-lived than it.
// r[impl session.native-handoff.session]
// r[impl session.native-handoff.lifetime]
async fn start_native_session(
    conn: &mut Connection,
    accepting: &Session,
    tenant: Option<(TenantId, konklav_core::MembershipId)>,
    jkt: &str,
    lifetime: Duration,
) -> Result<(Session, RefreshToken, Cursor), ApiError> {
    let id = SessionId::new_v7();
    let refresh = RefreshToken::generate(id);
    // The accepting session's expiry already holds the instance's session
    // lifetime and any identity provider's cap, counted from its sign-in.
    let expires_at = (Utc::now() + lifetime).min(accepting.expires_at);
    let (session, cursor) = sessions::insert(
        conn,
        NewSession {
            dpop_jkt: Some(jkt.to_owned()),
            id,
            subject_id: accepting.subject_id,
            credential_id: accepting.credential()?,
            stage: Stage::Identity,
            client_kind: ClientKind::Native,
            amr: accepting.amr.clone(),
            auth_time: accepting.auth_time,
            flags: accepting.flags.clone(),
            impersonator_subject_id: None,
            parent_session_id: None,
            refresh_hash: refresh.hash(),
            expires_at,
        },
    )
    .await?;
    let (session, cursor) = match tenant {
        Some((tenant, membership)) => {
            sessions::select_tenant(conn, session.id, tenant, membership).await?
        }
        None => (session, cursor),
    };
    let session = match &accepting.identity_claims {
        Some(passed) => sessions::set_identity_claims(conn, session.id, passed).await?,
        None => session,
    };
    Ok((session, refresh, cursor))
}

/// A code presented after it was exchanged has leaked, so the session it
/// started is revoked.
// r[impl session.native-handoff.code]
async fn revoke_if_reused(conn: &mut Connection, id: uuid::Uuid) -> Result<(), ApiError> {
    let challenge = challenges::get(conn, id).await?;
    let issued = serde_json::from_value::<CodeDetails>(challenge.details)
        .ok()
        .and_then(|details| details.issued_session);
    if let (Some(session), Some(_)) = (issued, challenge.consumed_at) {
        let filter = sessions::SessionFilter {
            session: Some(session),
            ..Default::default()
        };
        sessions::revoke(conn, &filter, None, "native_code_reused").await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // r[verify session.native-handoff.redirect]
    #[test]
    fn only_loopback_callbacks_are_redirect_uris() {
        assert!(is_loopback_redirect("http://127.0.0.1:53682/callback"));
        assert!(is_loopback_redirect("http://[::1]:53682/callback"));
        assert!(is_loopback_redirect("http://127.0.0.1/callback"));
        for refused in [
            "http://localhost:53682/callback",
            "https://127.0.0.1:53682/callback",
            "http://127.0.0.2:53682/callback",
            "http://example.com/callback",
            "http://127.0.0.1:53682/other",
            "http://127.0.0.1:53682/callback/",
            "http://127.0.0.1:53682/callback?x=1",
            "http://127.0.0.1:53682/callback#x",
            "http://user@127.0.0.1:53682/callback",
            "http://0x7f.1:53682/callback",
            "com.example.app:/callback",
            "",
        ] {
            assert!(!is_loopback_redirect(refused), "{refused}");
        }
    }

    #[test]
    fn app_names_are_checked() {
        assert!(is_app_name("konklav-cli"));
        assert!(!is_app_name("Konklav CLI"));
        assert!(!is_app_name(""));
    }
}
