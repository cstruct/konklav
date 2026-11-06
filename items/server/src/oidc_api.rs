//! Konklav as an OpenID provider: authorization with a login hand-off,
//! the token endpoint, userinfo and discovery.
//!
//! 1. `GET /v1/oauth2/authorize` validates the client and request, keeps
//!    them as a challenge bound to the browser by a cookie, and redirects to
//!    the login application with `login_request=<id>`.
//! 2. The login application signs the subject in through the `/v1` API and
//!    calls `POST /v1/oauth2/login-requests/{id}/accept` with that session's
//!    access token. Konklav checks `max_age`, `acr_values` and any requested
//!    tenant, and answers with the URL to send the browser to.
//! 3. `GET /v1/oauth2/authorize/resume` checks the browser is the one that
//!    started, and redirects to the client with a single-use code.
//! 4. The client exchanges the code at `POST /v1/oauth2/token` (with PKCE)
//!    for tokens of a new session, a child of the login application's.

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use diesel_async::AsyncConnection;
use konklav_authn::{RefreshToken, generate_secret, hash_challenge_secret};
use konklav_core::{SessionId, TenantId};
use konklav_store::challenges::{self, Challenge, NewChallenge, Purpose};
use konklav_store::oidc_clients::{self, ClientKind, OidcClient};
use konklav_store::sessions::{
    self, ClientKind as SessionClient, NewSession, RequestedClaims, Session, Stage,
};
use konklav_store::{Connection, credentials};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::claims_hook::ClaimsFor;
use crate::config::DpopRequirement;
use crate::cookies::{Cookie, SameSite};
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::oidc::{self, OpenIdProvider, Selection};
use crate::subject_api::{self, Started};
use crate::{AppState, cors, dpop, issue};

/// Binds a login request to the browser that started it. Lax: the browser
/// comes back from the login application by navigation.
const AUTHORIZE_COOKIE: Cookie = Cookie {
    name: "konklav_authorize",
    same_site: SameSite::Lax,
};
const LOGIN_REQUEST_MINUTES: i64 = 10;
const CODE_SECONDS: i64 = 60;

pub fn routes(state: &AppState) -> Router<AppState> {
    // Browser apps registered as public clients call these directly.
    let cors = || middleware::from_fn_with_state(state.clone(), cors::clients);
    Router::new()
        .route(
            "/oauth2/token",
            post(token).options(cors::preflight).layer(cors()),
        )
        .route(
            "/oauth2/userinfo",
            get(userinfo_get)
                .post(userinfo_post)
                .options(cors::preflight)
                .layer(cors()),
        )
        .route(
            "/oauth2/revoke",
            post(revoke).options(cors::preflight).layer(cors()),
        )
        .route("/oauth2/authorize", get(authorize_get).post(authorize_post))
        .route("/oauth2/authorize/resume", get(resume))
        .route("/oauth2/login-requests/{id}", get(login_request))
        .route("/oauth2/login-requests/{id}/accept", post(accept))
        .route("/oauth2/login-requests/{id}/reject", post(reject))
        .route("/oauth2/logout", get(logout))
        .route("/oauth2/peer/events", post(peer_events))
        .route("/oauth2/peer/subjects", post(peer_subject))
}

fn provider(state: &AppState) -> Result<&OpenIdProvider, ApiError> {
    state
        .auth
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::not_found("OpenID provider"))
}

pub(crate) fn endpoint(state: &AppState, path: &str) -> String {
    format!(
        "{}/v1/oauth2/{path}",
        state.auth.issuer.trim_end_matches('/')
    )
}

/// `GET /.well-known/openid-configuration`
// r[impl oidc.provider.discovery]
pub async fn discovery(State(state): State<AppState>) -> Result<Response, ApiError> {
    let provider = provider(&state)?;
    let mut scopes = vec!["openid", "email", "phone", "groups"];
    let mut claims = vec![
        "iss",
        "sub",
        "aud",
        "azp",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "amr",
        "acr",
        "sid",
        "email",
        "email_verified",
        "phone_number",
        "phone_number_verified",
        "groups",
    ];
    for (scope, passed) in state.auth.identity_providers.passed() {
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
        for claim in passed {
            if !claims.contains(&claim.as_str()) {
                claims.push(claim);
            }
        }
    }
    if let Some(hook) = &provider.claims_hook {
        scopes.extend(
            hook.scopes()
                .filter(|scope| !scopes.contains(scope))
                .collect::<Vec<_>>(),
        );
        for claim in hook.claims() {
            if !claims.contains(&claim) {
                claims.push(claim);
            }
        }
    }
    let document = serde_json::json!({
        "issuer": state.auth.issuer,
        "authorization_endpoint": endpoint(&state, "authorize"),
        "token_endpoint": endpoint(&state, "token"),
        "userinfo_endpoint": endpoint(&state, "userinfo"),
        "revocation_endpoint": endpoint(&state, "revoke"),
        "end_session_endpoint": endpoint(&state, "logout"),
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "konklav_peer_events_endpoint": endpoint(&state, "peer/events"),
        "konklav_peer_subjects_endpoint": endpoint(&state, "peer/subjects"),
        "jwks_uri": provider.jwks_uri,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            JWT_BEARER_GRANT
        ],
        "subject_types_supported": ["public"],
        // r[impl oidc.provider.algorithms]
        "id_token_signing_alg_values_supported": provider.algorithms(),
        "code_challenge_methods_supported": ["S256"],
        // r[impl oidc.provider.dpop.discovery]
        "dpop_signing_alg_values_supported": konklav_token::PROOF_ALGORITHMS,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256", "ES384", "RS256", "PS256", "EdDSA"],
        "scopes_supported": scopes,
        "claims_supported": claims,
        "acr_values_supported": [oidc::ACR_SINGLE, oidc::ACR_MULTI],
        "authorization_response_iss_parameter_supported": true,
        // r[impl oidc.provider.request-objects]
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "claims_parameter_supported": true,
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
    });
    Ok((
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(document),
    )
        .into_response())
}

// --- Authorization ------------------------------------------------------------

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    max_age: Option<i64>,
    acr_values: Option<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    request: Option<String>,
    request_uri: Option<String>,
    claims: Option<String>,
    dpop_jkt: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RequestDetails {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    state: Option<String>,
    nonce: Option<String>,
    /// Absent only for a confidential client registered without PKCE.
    #[serde(default)]
    code_challenge: Option<String>,
    max_age: Option<i64>,
    acr_values: Option<String>,
    tenant: Option<TenantId>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    login_hint: Option<String>,
    /// When the request started, as a Unix time; `prompt=login` needs a
    /// sign-in after it.
    #[serde(default)]
    requested_at: i64,
    /// The hash of the secret `accept` or `reject` put in `redirect_to`, set
    /// once the request is answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acceptance_hash: Option<String>,
    /// The error the login application refused the request with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refusal: Option<String>,
    /// Single claims asked for with the `claims` parameter.
    #[serde(default)]
    claims: RequestedClaims,
    /// The DPoP key thumbprint the code is bound to (`dpop_jkt`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dpop_jkt: Option<String>,
}

impl RequestDetails {
    fn prompts(&self, value: &str) -> bool {
        self.prompt
            .as_deref()
            .is_some_and(|prompt| prompt.split_whitespace().any(|p| p == value))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct CodeDetails {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    nonce: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    claims: RequestedClaims,
    /// The client session the code was exchanged for, revoked if the code
    /// is presented again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_session: Option<SessionId>,
    /// The DPoP key thumbprint the authorization request bound the code to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dpop_jkt: Option<String>,
}

fn redirect_to(url: &str, params: &[(&str, &str)]) -> Response {
    let target =
        reqwest::Url::parse_with_params(url, params).map_or_else(|_| url.to_owned(), String::from);
    (StatusCode::SEE_OTHER, [(header::LOCATION, target)]).into_response()
}

/// An error sent back to the client's redirect URI (RFC 6749 4.1.2.1).
fn client_error(
    details_redirect: &str,
    error: &str,
    state: Option<&str>,
    issuer: &str,
) -> Response {
    let mut params = vec![("error", error), ("iss", issuer)];
    if let Some(state) = state {
        params.push(("state", state));
    }
    redirect_to(details_redirect, &params)
}

/// Secure unless browser clients are configured otherwise.
fn secure_cookies(state: &AppState) -> bool {
    state.auth.browser.as_ref().is_none_or(|b| b.secure_cookies)
}

fn cookie(state: &AppState, value: &str, max_age: i64) -> HeaderValue {
    AUTHORIZE_COOKIE.set(secure_cookies(state), value, max_age)
}

async fn active_client(conn: &mut Connection, id: &str) -> Option<OidcClient> {
    oidc_clients::get(conn, id)
        .await
        .ok()
        .filter(OidcClient::is_active)
}

/// `GET /v1/oauth2/authorize`
async fn authorize_get(
    State(state): State<AppState>,
    query: Result<Query<AuthorizeQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    match query {
        Ok(Query(query)) => error_page(authorize(&state, query).await),
        Err(rejection) => error_page(Err(ApiError::invalid_request(rejection.body_text()))),
    }
}

/// `POST /v1/oauth2/authorize`, the same request as a form.
async fn authorize_post(
    State(state): State<AppState>,
    form: Result<Form<AuthorizeQuery>, axum::extract::rejection::FormRejection>,
) -> Response {
    match form {
        Ok(Form(query)) => error_page(authorize(&state, query).await),
        Err(rejection) => error_page(Err(ApiError::invalid_request(rejection.body_text()))),
    }
}

/// An error that can't go back to the client, as a page for the person
/// whose browser is showing it.
// r[impl oidc.provider.error-page]
fn error_page(result: Result<Response, ApiError>) -> Response {
    let error = match result {
        Ok(response) => return response,
        Err(error) => error,
    };
    let escape = |text: &str| {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let code = serde_json::to_value(error.code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let page = format!(
        "<!doctype html><html lang=en><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width\">\
         <title>Sign-in failed</title>\
         <h1>Sign-in failed</h1><p>{}</p><p><small>{code}</small></p></html>",
        escape(&error.message)
    );
    let mut response = (error.code.status(), axum::response::Html(page)).into_response();
    response.extensions_mut().insert(error.code);
    response
}

// r[impl oidc.provider.code-flow]
// r[impl oidc.provider.login-handoff]
// r[impl oidc.provider.request-objects]
// r[impl oidc.provider.prompt]
async fn authorize(state: &AppState, query: AuthorizeQuery) -> Result<Response, ApiError> {
    let provider = provider(state)?;
    let mut conn = state.pool.get().await?;
    // Until the client and redirect URI are known good, errors go to the
    // browser, never to a redirect URI.
    let client_id = query.client_id.as_deref().unwrap_or_default();
    let client = active_client(&mut conn, client_id)
        .await
        .ok_or_else(|| ApiError::invalid_request("unknown client_id"))?;
    let redirect_uri = query
        .redirect_uri
        .as_deref()
        .filter(|uri| client.allows_redirect(uri))
        .ok_or_else(|| ApiError::invalid_request("redirect_uri is not registered"))?;
    let issuer = state.auth.issuer.as_str();
    let fail = |error: &str| client_error(redirect_uri, error, query.state.as_deref(), issuer);

    if query.request.is_some() {
        return Ok(fail("request_not_supported"));
    }
    if query.request_uri.is_some() {
        return Ok(fail("request_uri_not_supported"));
    }
    match query.response_type.as_deref() {
        Some("code") => {}
        None => return Ok(fail("invalid_request")),
        Some(_) => return Ok(fail("unsupported_response_type")),
    }
    // `plain` isn't supported, and is what a challenge without a method means.
    let code_challenge = match (
        &query.code_challenge,
        query.code_challenge_method.as_deref(),
    ) {
        (Some(challenge), Some("S256")) if is_code_challenge(challenge) => Some(challenge.clone()),
        (None, _) if !client.require_pkce => None,
        _ => return Ok(fail("invalid_request")),
    };
    // r[impl oidc.provider.dpop.code-binding]
    if query
        .dpop_jkt
        .as_deref()
        .is_some_and(|jkt| !is_thumbprint(jkt))
    {
        return Ok(fail("invalid_request"));
    }
    let prompt = query
        .prompt
        .as_deref()
        .map(|p| p.split_whitespace().collect::<Vec<_>>())
        .unwrap_or_default();
    if prompt.contains(&"none") && prompt.len() > 1 {
        return Ok(fail("invalid_request"));
    }
    let (scopes, tenant) = match granted_scopes(&client, query.scope.as_deref()) {
        Ok(granted) => granted,
        Err(error) => return Ok(fail(error)),
    };
    let Some(claims) = requested_claims(state, &client, query.claims.as_deref()) else {
        return Ok(fail("invalid_request"));
    };

    let id = uuid::Uuid::now_v7();
    let secret = generate_secret();
    let details = RequestDetails {
        client_id: client.id.clone(),
        redirect_uri: redirect_uri.to_owned(),
        scopes,
        state: query.state.clone(),
        nonce: query.nonce.clone(),
        code_challenge,
        max_age: query.max_age,
        acr_values: query.acr_values.clone(),
        tenant,
        prompt: (!prompt.is_empty()).then(|| prompt.join(" ")),
        login_hint: query.login_hint.clone(),
        requested_at: Utc::now().timestamp(),
        acceptance_hash: None,
        refusal: None,
        claims,
        dpop_jkt: query.dpop_jkt.clone(),
    };
    challenges::create(
        &mut conn,
        NewChallenge {
            id,
            purpose: Purpose::OidcAuthorize,
            subject_id: None,
            credential_id: None,
            mfa_factor_id: None,
            session_id: None,
            recipient: client.id.clone(),
            secret_hash: hash_challenge_secret(&id.to_string(), &secret),
            details: serde_json::to_value(&details).map_err(ApiError::internal)?,
            expires_at: Utc::now() + Duration::minutes(LOGIN_REQUEST_MINUTES),
        },
    )
    .await?;
    let login_url = client.login_url.as_deref().unwrap_or(&provider.login_url);
    let mut response = redirect_to(login_url, &[("login_request", &id.to_string())]);
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie(state, &format!("{id}.{secret}"), LOGIN_REQUEST_MINUTES * 60),
    );
    Ok(response)
}

/// The claims a `claims` parameter asks for that a scope the client is
/// registered for covers, or `None` when the parameter is malformed. Values
/// and `essential` don't matter: a missing claim is never an error.
// r[impl oidc.provider.claims-parameter]
fn requested_claims(
    state: &AppState,
    client: &OidcClient,
    raw: Option<&str>,
) -> Option<RequestedClaims> {
    let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
        return Some(RequestedClaims::default());
    };
    let serde_json::Value::Object(request) = serde_json::from_str(raw).ok()? else {
        return None;
    };
    // Hook and passed claims are only served from userinfo.
    let names = |member: &str, own_only: bool| match request.get(member) {
        None | Some(serde_json::Value::Null) => Some(Vec::new()),
        Some(serde_json::Value::Object(claims)) => Some(
            claims
                .keys()
                .filter(|claim| {
                    claim_scope(state, claim).is_some_and(|(scope, own)| {
                        client.allows_scope(scope) && (own || !own_only)
                    })
                })
                .cloned()
                .collect(),
        ),
        Some(_) => None,
    };
    Some(RequestedClaims {
        userinfo: names("userinfo", false)?,
        id_token: names("id_token", true)?,
    })
}

/// The scope that covers `claim`, and whether Konklav holds the claim
/// itself rather than a claims hook or an identity provider.
fn claim_scope<'a>(state: &'a AppState, claim: &str) -> Option<(&'a str, bool)> {
    if let Some((scope, _)) = oidc::OWN_SCOPES
        .iter()
        .find(|(_, claims)| claims.contains(&claim))
    {
        return Some((scope, true));
    }
    let hooked = state
        .auth
        .oidc
        .as_ref()
        .and_then(|provider| provider.claims_hook.as_ref())
        .and_then(|hook| hook.scope_of(claim));
    hooked
        .or_else(|| state.auth.identity_providers.passed_scope_of(claim))
        .map(|scope| (scope, false))
}

/// An S256 challenge: the base64url SHA-256 of a verifier, 43 characters
/// (RFC 7636 4.2 allows 43 to 128 unreserved characters).
/// A SHA-256 key thumbprint: 43 base64url characters.
fn is_thumbprint(jkt: &str) -> bool {
    jkt.len() == 43
        && jkt
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_code_challenge(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// The requested scopes the client may have, without repeats, and the
/// tenant a `tenant:` scope names. Others are dropped, but `openid` must be
/// requested, and at most one tenant.
// r[impl oidc.provider.scopes]
fn granted_scopes(
    client: &OidcClient,
    requested: Option<&str>,
) -> Result<(Vec<String>, Option<TenantId>), &'static str> {
    let requested: Vec<&str> = requested.unwrap_or_default().split_whitespace().collect();
    if !requested.contains(&"openid") {
        return Err("invalid_scope");
    }
    let mut scopes: Vec<String> = Vec::new();
    for scope in requested {
        if client.allows_scope(scope) && !scopes.iter().any(|s| s == scope) {
            scopes.push(scope.to_owned());
        }
    }
    let tenants: Vec<_> = scopes
        .iter()
        .filter_map(|s| s.strip_prefix("tenant:"))
        .collect();
    let tenant = match tenants.as_slice() {
        [] => None,
        [one] => Some(TenantId::from(
            one.parse::<uuid::Uuid>().map_err(|_| "invalid_scope")?,
        )),
        _ => return Err("invalid_scope"),
    };
    Ok((scopes, tenant))
}

async fn pending_request(
    conn: &mut Connection,
    id: &str,
) -> Result<(Challenge, RequestDetails), ApiError> {
    let unknown = || ApiError::not_found("login request");
    let id: uuid::Uuid = id.parse().map_err(|_| unknown())?;
    let challenge = challenges::get(conn, id).await.map_err(|_| unknown())?;
    if challenge.purpose != Purpose::OidcAuthorize.as_str() || !challenge.is_usable(Utc::now()) {
        return Err(unknown());
    }
    let details = serde_json::from_value(challenge.details.clone()).map_err(|_| unknown())?;
    Ok((challenge, details))
}

#[derive(Serialize)]
struct LoginRequestView {
    client_id: String,
    scopes: Vec<String>,
    tenant: Option<TenantId>,
    max_age: Option<i64>,
    acr_values: Option<String>,
    /// The request's `prompt`, such as `none` (answer without asking the
    /// person anything, or refuse with `login_required`) or `login` (ask
    /// them to sign in again).
    prompt: Option<String>,
    login_hint: Option<String>,
}

/// `GET /v1/oauth2/login-requests/{id}`: what the login application needs
/// to know to satisfy a request.
async fn login_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<LoginRequestView>, ApiError> {
    provider(&state)?;
    let mut conn = state.pool.get().await?;
    let (_, details) = pending_request(&mut conn, &id).await?;
    Ok(Json(LoginRequestView {
        client_id: details.client_id,
        scopes: details.scopes,
        tenant: details.tenant,
        max_age: details.max_age,
        acr_values: details.acr_values,
        prompt: details.prompt,
        login_hint: details.login_hint,
    }))
}

#[derive(Serialize)]
struct Accepted {
    redirect_to: String,
}

/// `POST /v1/oauth2/login-requests/{id}/accept`, with the login
/// application's access token.
// r[impl oidc.provider.tenant]
async fn accept(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Accepted>, ApiError> {
    provider(&state)?;
    subject_api::check_browser_request(&state.auth, &headers)?;
    let mut conn = state.pool.get().await?;
    let (_, session) = subject_api::authenticate(&state, &mut conn, &headers).await?;
    let (challenge, mut details) = pending_request(&mut conn, &id).await?;
    if details.refusal.is_some() {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "the request was already answered",
        ));
    }
    let unmet = |what: &str| ApiError::new(ErrorCode::Forbidden, what.to_owned());
    if session.stage == Stage::Partial || session.oidc_client_id.is_some() {
        return Err(unmet("sign in through the login application first"));
    }
    if let Some(max_age) = details.max_age
        && (Utc::now() - session.auth_time).num_seconds() > max_age
    {
        return Err(unmet(
            "the sign-in is older than the request's max_age; sign in again",
        ));
    }
    if let Some(acr_values) = &details.acr_values
        && !oidc::satisfies_acr(&session, acr_values)
    {
        return Err(unmet("the request needs a stronger sign-in (acr_values)"));
    }
    // r[impl oidc.provider.prompt]
    if details.prompts("login") && session.auth_time.timestamp() < details.requested_at {
        return Err(unmet(
            "the request asks for a new sign-in (prompt=login); sign in again",
        ));
    }
    if details.tenant.is_some() && session.tenant_id != details.tenant {
        return Err(unmet("select the requested tenant first"));
    }
    // The secret goes only to the accepting browser, which must present it
    // together with the starting browser's cookie, so a request started in
    // one browser can't be completed with a session from another.
    // r[impl oidc.provider.login-handoff]
    let acceptance = generate_secret();
    details.acceptance_hash = Some(acceptance_hash(challenge.id, &acceptance));
    let stored = serde_json::to_value(&details).map_err(ApiError::internal)?;
    if !challenges::attach_session(&mut conn, challenge.id, session.id, &stored).await? {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "the request was already accepted",
        ));
    }
    Ok(Json(Accepted {
        redirect_to: format!(
            "{}?login_request={}&acceptance={acceptance}",
            endpoint(&state, "authorize/resume"),
            challenge.id
        ),
    }))
}

#[derive(Deserialize)]
struct Refusal {
    error: String,
}

/// Errors a login application may refuse a request with.
const REFUSALS: [&str; 5] = [
    "login_required",
    "interaction_required",
    "consent_required",
    "account_selection_required",
    "access_denied",
];

/// `POST /v1/oauth2/login-requests/{id}/reject`: the login application
/// refuses the request, as it must for `prompt=none` when nobody is signed
/// in. Like `accept`, it returns where to send the browser, which then
/// carries the error to the client.
// r[impl oidc.provider.login-refusal]
async fn reject(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(refusal): ApiJson<Refusal>,
) -> Result<Json<Accepted>, ApiError> {
    provider(&state)?;
    subject_api::check_browser_request(&state.auth, &headers)?;
    if !REFUSALS.contains(&refusal.error.as_str()) {
        return Err(ApiError::invalid_request(format!(
            "error must be one of {}",
            REFUSALS.join(", ")
        )));
    }
    let mut conn = state.pool.get().await?;
    let (challenge, mut details) = pending_request(&mut conn, &id).await?;
    if challenge.session_id.is_some() || details.refusal.is_some() {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "the request was already answered",
        ));
    }
    let acceptance = generate_secret();
    details.acceptance_hash = Some(acceptance_hash(challenge.id, &acceptance));
    details.refusal = Some(refusal.error);
    let stored = serde_json::to_value(&details).map_err(ApiError::internal)?;
    challenges::set_details(&mut conn, challenge.id, &stored).await?;
    Ok(Json(Accepted {
        redirect_to: format!(
            "{}?login_request={}&acceptance={acceptance}",
            endpoint(&state, "authorize/resume"),
            challenge.id
        ),
    }))
}

fn acceptance_hash(request: uuid::Uuid, secret: &str) -> String {
    STANDARD.encode(hash_challenge_secret(
        &format!("{request}.acceptance"),
        secret,
    ))
}

#[derive(Deserialize)]
struct ResumeQuery {
    login_request: String,
    acceptance: Option<String>,
}

/// `GET /v1/oauth2/authorize/resume`
async fn resume(
    State(state): State<AppState>,
    Query(query): Query<ResumeQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    provider(&state)?;
    let foreign = || ApiError::invalid_request("this browser didn't start the request");
    let cookie_value = AUTHORIZE_COOKIE
        .read(&headers, secure_cookies(&state))
        .ok_or_else(foreign)?;
    let (cookie_id, secret) = cookie_value.split_once('.').ok_or_else(foreign)?;
    if cookie_id != query.login_request {
        return Err(foreign());
    }
    let mut conn = state.pool.get().await?;
    let (challenge, details) = pending_request(&mut conn, &query.login_request).await?;
    let matches: bool = hash_challenge_secret(&challenge.id.to_string(), secret)
        .ct_eq(&challenge.secret_hash)
        .into();
    if !matches {
        return Err(foreign());
    }
    let accepted_here = match (&details.acceptance_hash, &query.acceptance) {
        (Some(hash), Some(acceptance)) => bool::from(
            acceptance_hash(challenge.id, acceptance)
                .as_bytes()
                .ct_eq(hash.as_bytes()),
        ),
        _ => false,
    };
    if !accepted_here {
        return Err(foreign());
    }
    if let Some(error) = &details.refusal {
        if !challenges::consume(&mut conn, challenge.id, Utc::now()).await? {
            return Err(foreign());
        }
        let mut response = client_error(
            &details.redirect_uri,
            error,
            details.state.as_deref(),
            &state.auth.issuer,
        );
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie(&state, "", 0));
        return Ok(response);
    }
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
            purpose: Purpose::OidcCode,
            subject_id: None,
            credential_id: None,
            mfa_factor_id: None,
            session_id: Some(session),
            recipient: details.client_id.clone(),
            secret_hash: hash_challenge_secret(&code_id.to_string(), &code_secret),
            details: serde_json::to_value(CodeDetails {
                client_id: details.client_id.clone(),
                redirect_uri: details.redirect_uri.clone(),
                scopes: details.scopes.clone(),
                nonce: details.nonce.clone(),
                code_challenge: details.code_challenge.clone(),
                claims: details.claims.clone(),
                issued_session: None,
                dpop_jkt: details.dpop_jkt.clone(),
            })
            .map_err(ApiError::internal)?,
            expires_at: Utc::now() + Duration::seconds(CODE_SECONDS),
        },
    )
    .await?;
    let code = format!("{code_id}.{code_secret}");
    let mut params = vec![("code", code.as_str()), ("iss", state.auth.issuer.as_str())];
    if let Some(client_state) = &details.state {
        params.push(("state", client_state));
    }
    let mut response = redirect_to(&details.redirect_uri, &params);
    response
        .headers_mut()
        .append(header::SET_COOKIE, cookie(&state, "", 0));
    Ok(response)
}

// --- Token endpoint -----------------------------------------------------------

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: Option<String>,
    /// For revocation.
    token: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    /// For the peer endpoints.
    after: Option<i64>,
    subject: Option<String>,
    /// For the JWT bearer grant.
    assertion: Option<String>,
}

const JWT_BEARER_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// An RFC 6749 token-endpoint error.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"error": error, "error_description": description})),
    )
        .into_response()
}

/// `invalid_client`, with a basic challenge when the client tried basic
/// credentials (RFC 6749 5.2).
// r[impl oidc.provider.token-errors]
fn client_unauthenticated(headers: &HeaderMap) -> Response {
    let mut response = oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "client authentication failed",
    );
    let tried_basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Basic "));
    if tried_basic {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"konklav\""),
        );
    }
    response
}

/// Whether `client`'s grants need a DPoP proof: by its registration, or by
/// the provider's policy.
// r[impl oidc.provider.dpop.required]
// r[impl oidc.provider.dpop.policy]
fn dpop_required(state: &AppState, client: &OidcClient) -> bool {
    let policy = state
        .auth
        .oidc
        .as_ref()
        .map_or(DpopRequirement::None, |provider| provider.require_dpop);
    client.require_dpop
        || match policy {
            DpopRequirement::None => false,
            DpopRequirement::PublicClients => client.kind == ClientKind::Public,
            DpopRequirement::All => true,
        }
}

/// `DPoP` for a bound session's tokens, `Bearer` otherwise.
// r[impl oidc.provider.dpop.token]
fn token_type(session: &Session) -> &'static str {
    if session.dpop_jkt.is_some() {
        "DPoP"
    } else {
        "Bearer"
    }
}

fn invalid_grant(description: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

/// Authenticates the client: a `private_key_jwt` assertion, or a secret in
/// HTTP basic credentials or the form, or (public clients) just its id.
async fn authenticate_client(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
    form: &TokenRequest,
) -> Option<OidcClient> {
    if let Some(assertion) = &form.client_assertion {
        if form.client_assertion_type.as_deref() != Some(JWT_BEARER_ASSERTION) {
            return None;
        }
        return authenticate_assertion(state, conn, assertion).await;
    }
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|v| STANDARD.decode(v).ok())
        .and_then(|v| String::from_utf8(v).ok())
        .and_then(|v| {
            let (id, secret) = v.split_once(':')?;
            let decode = |s: &str| {
                percent_encoding::percent_decode_str(s)
                    .decode_utf8_lossy()
                    .into_owned()
            };
            Some((decode(id), decode(secret)))
        });
    let (id, secret) = match basic {
        Some((id, secret)) => (id, Some(secret)),
        None => (form.client_id.clone()?, form.client_secret.clone()),
    };
    let client = active_client(conn, &id).await?;
    match (client.kind, &client.secret_hash, secret) {
        (ClientKind::Public, _, None) => Some(client),
        (ClientKind::Confidential, Some(hash), Some(secret)) => {
            let presented = Sha256::digest(secret.as_bytes());
            bool::from(presented.as_slice().ct_eq(hash)).then_some(client)
        }
        _ => None,
    }
}

/// Authenticates a client by a JWT it signed with a key from its
/// registered `jwks` (RFC 7523): `iss` and `sub` are the client id, `aud`
/// names the token endpoint or the issuer, and each `jti` works once.
// r[impl oidc.provider.client-credentials]
async fn authenticate_assertion(
    state: &AppState,
    conn: &mut Connection,
    assertion: &str,
) -> Option<OidcClient> {
    #[derive(Deserialize)]
    struct AssertionClaims {
        iss: String,
        sub: String,
        jti: String,
        exp: i64,
    }
    let unverified = jsonwebtoken::dangerous::insecure_decode::<AssertionClaims>(assertion).ok()?;
    let client_id = unverified.claims.iss;
    let client = active_client(conn, &client_id).await?;
    let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(client.jwks.clone()?).ok()?;
    let header = jsonwebtoken::decode_header(assertion).ok()?;
    let symmetric = matches!(
        header.alg,
        jsonwebtoken::Algorithm::HS256
            | jsonwebtoken::Algorithm::HS384
            | jsonwebtoken::Algorithm::HS512
    );
    if symmetric {
        return None;
    }
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid),
        None if jwks.keys.len() == 1 => jwks.keys.first(),
        None => None,
    }?;
    let key = jsonwebtoken::DecodingKey::from_jwk(jwk).ok()?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_issuer(&[&client_id]);
    validation.sub = Some(client_id.clone());
    validation.set_audience(&[endpoint(state, "token"), state.auth.issuer.clone()]);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud", "jti"]);
    validation.leeway = 30;
    let claims = jsonwebtoken::decode::<AssertionClaims>(assertion, &key, &validation)
        .ok()?
        .claims;
    if claims.sub != client_id {
        return None;
    }
    let expires = chrono::DateTime::from_timestamp(claims.exp, 0)?;
    konklav_store::client_assertions::record(conn, &client_id, &claims.jti, expires)
        .await
        .ok()?
        .then_some(client)
}

#[derive(Serialize)]
struct Tokens {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    scope: String,
}

/// `POST /v1/oauth2/token`
async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Response, ApiError> {
    provider(&state)?;
    let mut conn = state.pool.get().await?;
    let expected = dpop::Expected {
        method: "POST",
        urls: dpop::Expected::endpoint(&state, "token"),
        access_token: None,
        bound_to: None,
    };
    let proof = match dpop::check(&state, &mut conn, &headers, &expected).await? {
        Ok(proof) => proof,
        Err(reason) => return Ok(dpop::invalid_token_request(reason)),
    };
    let jkt = proof.as_ref().map(|proof| proof.jkt.as_str());
    // The assertion is the credential: no client authenticates this grant.
    if form.grant_type.as_deref() == Some(JWT_BEARER_GRANT) {
        return jwt_bearer_grant(&state, &mut conn, form.assertion.as_deref(), jkt).await;
    }
    let Some(client) = authenticate_client(&state, &mut conn, &headers, &form).await else {
        return Ok(client_unauthenticated(&headers));
    };
    if dpop_required(&state, &client) && jkt.is_none() {
        return Ok(dpop::invalid_token_request(
            "this client must send a DPoP proof",
        ));
    }
    Ok(match form.grant_type.as_deref().unwrap_or_default() {
        "authorization_code" => code_grant(&state, &mut conn, &client, &form, jkt).await?,
        "refresh_token" if client.refresh => {
            refresh_grant(&state, &mut conn, &client, &form, jkt).await?
        }
        "refresh_token" => oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "refresh is off for this client",
        ),
        "client_credentials" if client.service_subject.is_some() => {
            client_credentials_grant(&state, &mut conn, &client, jkt).await?
        }
        "client_credentials" => oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client isn't bound to a service principal",
        ),
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "use authorization_code, refresh_token or client_credentials",
        ),
    })
}

/// `jkt` is the key thumbprint of the request's DPoP proof, if it had one.
// r[impl oidc.provider.dpop.token]
async fn code_grant(
    state: &AppState,
    conn: &mut Connection,
    client: &OidcClient,
    form: &TokenRequest,
    jkt: Option<&str>,
) -> Result<Response, ApiError> {
    let Some((id, secret)) = form.code.as_deref().and_then(|c| c.split_once('.')) else {
        return Ok(invalid_grant("malformed code"));
    };
    let Ok(id) = id.parse::<uuid::Uuid>() else {
        return Ok(invalid_grant("malformed code"));
    };
    let Ok(challenge) = challenges::get(conn, id).await else {
        return Ok(invalid_grant("unknown code"));
    };
    let matches: bool = hash_challenge_secret(&id.to_string(), secret)
        .ct_eq(&challenge.secret_hash)
        .into();
    let Ok(details) = serde_json::from_value::<CodeDetails>(challenge.details.clone()) else {
        return Ok(invalid_grant("unknown code"));
    };
    if !matches
        || challenge.purpose != Purpose::OidcCode.as_str()
        || details.client_id != client.id
        || form.redirect_uri.as_deref() != Some(details.redirect_uri.as_str())
    {
        return Ok(invalid_grant(
            "the code wasn't issued for this client and redirect URI",
        ));
    }
    // A verifier without a challenge is refused too, so a request can't
    // be downgraded to skip PKCE.
    // r[impl oidc.provider.code-flow]
    let verified = match (&details.code_challenge, form.code_verifier.as_deref()) {
        (Some(expected), Some(verifier)) => {
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            bool::from(challenge.as_bytes().ct_eq(expected.as_bytes()))
        }
        (None, None) => true,
        _ => false,
    };
    if !verified {
        return Ok(invalid_grant("PKCE verification failed"));
    }
    // A code bound with `dpop_jkt` is exchanged only with that key's proof.
    // r[impl oidc.provider.dpop.code-binding]
    if details.dpop_jkt.is_some() && details.dpop_jkt.as_deref() != jkt {
        return Ok(dpop::invalid_token_request(
            "the code is bound to another DPoP key",
        ));
    }
    // Consuming the code and recording the session it issued commit
    // together, so a concurrent second use waits and then finds the session.
    let outcome = conn
        .transaction::<_, ApiError, _>(async |conn| {
            if !challenges::consume(conn, id, Utc::now()).await? {
                return Ok(Err("the code was used or expired"));
            }
            let Some(parent) = challenge.session_id else {
                return Ok(Err("unknown code"));
            };
            let parent = sessions::get(conn, parent).await?;
            if !parent.is_active_at(Utc::now()) || !subject_api::still_valid(conn, &parent).await? {
                return Ok(Err("the sign-in has ended"));
            }
            let (session, refresh) =
                start_client_session(conn, &parent, client, &details.scopes, &details.claims, jkt)
                    .await?;
            let issued = CodeDetails {
                issued_session: Some(session.id),
                ..details.clone()
            };
            let issued = serde_json::to_value(issued).map_err(ApiError::internal)?;
            challenges::set_details(conn, id, &issued).await?;
            Ok(Ok((session, refresh)))
        })
        .await?;
    let (session, refresh) = match outcome {
        Ok(issued) => issued,
        Err(reason) => {
            revoke_if_reused(conn, id).await?;
            return Ok(invalid_grant(reason));
        }
    };
    let tokens = tokens_for(
        state,
        conn,
        client,
        &session,
        details.nonce.as_deref(),
        &refresh,
    )
    .await?;
    Ok(tokens)
}

/// A code presented after it was exchanged has leaked, so the session it
/// issued, with its tokens, is revoked (RFC 6749, section 4.1.2).
// r[impl oidc.provider.code-reuse]
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
        sessions::revoke(conn, &filter, None, "authorization_code_reused").await?;
    }
    Ok(())
}

/// A session for the client, a child of the login application's: same
/// subject, credential, tenant and authentication, ending with it.
async fn start_client_session(
    conn: &mut Connection,
    parent: &Session,
    client: &OidcClient,
    scopes: &[String],
    claims: &RequestedClaims,
    dpop_jkt: Option<&str>,
) -> Result<(Session, RefreshToken), ApiError> {
    let id = SessionId::new_v7();
    let refresh = RefreshToken::generate(id);
    let session = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let (session, _) = sessions::insert(
                conn,
                NewSession {
                    dpop_jkt: dpop_jkt.map(str::to_owned),
                    id,
                    subject_id: parent.subject_id,
                    credential_id: parent.credential_id,
                    stage: Stage::Identity,
                    client_kind: SessionClient::Native,
                    amr: parent.amr.clone(),
                    auth_time: parent.auth_time,
                    flags: parent.flags.clone(),
                    impersonator_subject_id: parent.impersonator_subject_id,
                    parent_session_id: Some(parent.id),
                    refresh_hash: refresh.hash(),
                    expires_at: parent.expires_at,
                },
            )
            .await?;
            if let (Some(tenant), Some(membership)) = (parent.tenant_id, parent.membership_id) {
                sessions::select_tenant(conn, session.id, tenant, membership).await?;
            }
            let session =
                sessions::bind_client(conn, session.id, &client.id, scopes, claims).await?;
            // Claims passed from an identity provider last as long as the
            // sign-in they came with.
            Ok(match &parent.identity_claims {
                Some(passed) => sessions::set_identity_claims(conn, session.id, passed).await?,
                None => session,
            })
        })
        .await?;
    Ok((session, refresh))
}

async fn tokens_for(
    state: &AppState,
    conn: &mut Connection,
    client: &OidcClient,
    session: &Session,
    nonce: Option<&str>,
    refresh: &RefreshToken,
) -> Result<Response, ApiError> {
    let provider = provider(state)?;
    let access = issue::access_token(conn, &state.auth, session).await?;
    // `groups` from the scopes, and what the client asked for in the ID
    // token; the other scopes' claims are in userinfo.
    let groups: Vec<String> = session
        .oidc_scopes
        .iter()
        .filter(|scope| *scope == "groups")
        .cloned()
        .collect();
    let credential = credentials::get(conn, session.credential_id).await?;
    let claims = oidc::claims(
        conn,
        client,
        Selection {
            scopes: &groups,
            claims: &session.oidc_claims.id_token,
        },
        session.subject_id,
        &credential,
    )
    .await?;
    let id_token = oidc::id_token(&state.auth, provider, client, session, nonce, &claims)?;
    let body = Tokens {
        access_token: access.access_token,
        token_type: token_type(session),
        expires_in: access.expires_in,
        id_token,
        refresh_token: client.refresh.then(|| refresh.as_str().to_owned()),
        scope: session.oidc_scopes.join(" "),
    };
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response())
}

/// The refresh grant. A bound session's refresh token needs a proof made
/// with its key, checked before anything rotates, so a refused refresh
/// leaves the session as it was.
// r[impl token.refresh.dpop-bound]
async fn refresh_grant(
    state: &AppState,
    conn: &mut Connection,
    client: &OidcClient,
    form: &TokenRequest,
    jkt: Option<&str>,
) -> Result<Response, ApiError> {
    let Some(presented) = form.refresh_token.as_deref() else {
        return Ok(invalid_grant("refresh_token is required"));
    };
    if let Ok(parsed) = RefreshToken::parse(presented)
        && let Ok(session) = sessions::get(conn, parsed.session()).await
        && session.dpop_jkt.is_some()
        && session.dpop_jkt.as_deref() != jkt
    {
        return Ok(dpop::invalid_token_request(
            "the refresh token is bound to another DPoP key",
        ));
    }
    match subject_api::rotate(conn, presented, Some(&client.id), jkt).await {
        Ok(Started {
            session, refresh, ..
        }) => tokens_for(state, conn, client, &session, None, &refresh).await,
        Err(_) => Ok(invalid_grant(
            "the refresh token is invalid or its session ended",
        )),
    }
}

/// Tokens for the client's service principal: a short session, as long as
/// one access token, with no refresh or ID token.
// r[impl oidc.provider.client-credentials]
async fn client_credentials_grant(
    state: &AppState,
    conn: &mut Connection,
    client: &OidcClient,
    dpop_jkt: Option<&str>,
) -> Result<Response, ApiError> {
    let unbound = || {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client's service principal can't sign in",
        )
    };
    let Some(credential) =
        credentials::find_active(conn, credentials::CredentialKind::Client, &client.id).await?
    else {
        return Ok(unbound());
    };
    let principal = konklav_store::subjects::get(conn, credential.subject_id).await?;
    if principal.state != konklav_store::subjects::SubjectState::Active {
        return Ok(unbound());
    }
    let id = SessionId::new_v7();
    let now = Utc::now();
    let session = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let (session, _) = sessions::insert(
                conn,
                NewSession {
                    dpop_jkt: dpop_jkt.map(str::to_owned),
                    id,
                    subject_id: credential.subject_id,
                    credential_id: credential.id,
                    stage: Stage::Identity,
                    client_kind: SessionClient::Native,
                    amr: vec!["sk".to_owned()],
                    auth_time: now,
                    flags: Vec::new(),
                    impersonator_subject_id: None,
                    parent_session_id: None,
                    // Never presented: these sessions can't be refreshed.
                    refresh_hash: Sha256::digest(generate_secret().as_bytes()).to_vec(),
                    expires_at: now + state.auth.access_ttl,
                },
            )
            .await?;
            Ok(sessions::bind_client(
                conn,
                session.id,
                &client.id,
                &[],
                &RequestedClaims::default(),
            )
            .await?)
        })
        .await?;
    let access = issue::access_token(conn, &state.auth, &session).await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "access_token": access.access_token,
            "token_type": "Bearer",
            "expires_in": access.expires_in,
        })),
    )
        .into_response())
}

// --- Revocation and logout -------------------------------------------------------

/// `POST /v1/oauth2/revoke` (RFC 7009): revokes the session behind a refresh
/// or access token the client was issued. Answers 200 for tokens it doesn't
/// know, as the RFC asks.
// r[impl oidc.provider.revocation]
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Response, ApiError> {
    provider(&state)?;
    let mut conn = state.pool.get().await?;
    let Some(client) = authenticate_client(&state, &mut conn, &headers, &form).await else {
        return Ok(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        ));
    };
    let token = form.token.as_deref().unwrap_or_default();
    let session = if token.matches('.').count() == 2 {
        // An access token: its signature and audience must check out, but an
        // expired one is fine to revoke.
        match konklav_token::decode_claims_unverified(token) {
            Some(claims) if claims.aud == client.audience => {
                let verified = subject_api::verify_access_token_for(
                    &state,
                    &mut conn,
                    token,
                    &client.audience,
                )
                .await;
                verified.ok().map(|(_, session)| session)
            }
            _ => None,
        }
    } else {
        match RefreshToken::parse(token) {
            Ok(refresh) => {
                let matches =
                    sessions::refresh_matches(&mut conn, refresh.session(), &refresh.hash())
                        .await?;
                if matches {
                    sessions::get(&mut conn, refresh.session()).await.ok()
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    };
    if let Some(session) =
        session.filter(|s| s.oidc_client_id.as_deref() == Some(client.id.as_str()))
    {
        let filter = sessions::SessionFilter {
            session: Some(session.id),
            ..Default::default()
        };
        sessions::revoke(&mut conn, &filter, None, "token_revoked").await?;
    }
    Ok(([(header::CACHE_CONTROL, "no-store")], StatusCode::OK).into_response())
}

#[derive(Deserialize)]
struct LogoutQuery {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
}

/// `GET /v1/oauth2/logout` (RP-initiated logout): with a valid
/// `id_token_hint`, ends the sign-in the client's session came from, and
/// with it every client session started from it. Then redirects to a
/// registered `post_logout_redirect_uri`, if one was given.
// r[impl oidc.provider.logout]
async fn logout(
    State(state): State<AppState>,
    Query(query): Query<LogoutQuery>,
) -> Result<Response, ApiError> {
    let provider = provider(&state)?;
    let mut conn = state.pool.get().await?;
    let hinted = match &query.id_token_hint {
        Some(hint) => oidc::verify_own_id_token(&mut conn, &state.auth, provider, hint).await?,
        None => None,
    };
    let client_id = hinted
        .as_ref()
        .map(|(client, _)| client.clone())
        .or(query.client_id.clone());
    let mut signed_out = false;
    if let Some((client, sid)) = &hinted
        && let Ok(session) = sessions::get(&mut conn, *sid).await
        && session.oidc_client_id.as_deref() == Some(client.as_str())
    {
        let filter = sessions::SessionFilter {
            session: Some(session.parent_session_id.unwrap_or(session.id)),
            ..Default::default()
        };
        sessions::revoke(&mut conn, &filter, None, "signed_out").await?;
        signed_out = true;
    }
    let Some(uri) = &query.post_logout_redirect_uri else {
        return Ok(Json(serde_json::json!({"signed_out": signed_out})).into_response());
    };
    let registered = match &client_id {
        Some(id) => oidc_clients::get(&mut conn, id)
            .await
            .is_ok_and(|client| client.post_logout_redirect_uris.iter().any(|u| u == uri)),
        None => false,
    };
    if !registered {
        return Err(ApiError::invalid_request(
            "post_logout_redirect_uri is not registered for the client",
        ));
    }
    let mut params = Vec::new();
    if let Some(client_state) = &query.state {
        params.push(("state", client_state.as_str()));
    }
    Ok(redirect_to(uri, &params))
}

/// The JWT bearer grant (RFC 7523) for workloads: a token from an identity
/// provider that accepts workloads signs in the service principal holding a
/// federated credential for its `sub`. The access token has this instance's
/// audience and lasts at most one access token.
// r[impl federation.jwt-bearer]
async fn jwt_bearer_grant(
    state: &AppState,
    conn: &mut Connection,
    assertion: Option<&str>,
    dpop_jkt: Option<&str>,
) -> Result<Response, ApiError> {
    #[derive(Deserialize)]
    struct Issuer {
        iss: String,
    }
    let Some(assertion) = assertion else {
        return Ok(invalid_grant("assertion is required"));
    };
    let Ok(unverified) = jsonwebtoken::dangerous::insecure_decode::<Issuer>(assertion) else {
        return Ok(invalid_grant("malformed assertion"));
    };
    let Some(provider) = state
        .auth
        .identity_providers
        .iter()
        .find(|p| p.settings.workloads && p.settings.issuer == unverified.claims.iss)
    else {
        return Ok(invalid_grant(
            "the assertion's issuer isn't trusted for workloads",
        ));
    };
    let audiences = [state.auth.issuer.clone(), endpoint(state, "token")];
    let verified = match provider.verify_assertion(assertion, &audiences).await {
        Ok(verified) => verified,
        Err(error) => {
            tracing::info!(%error, "JWT bearer assertion refused");
            return Ok(invalid_grant("the assertion is invalid"));
        }
    };
    let identifier = credentials::federated_identifier(&provider.settings.id, &verified.sub);
    let Some(credential) =
        credentials::find_active(conn, credentials::CredentialKind::Federated, &identifier).await?
    else {
        return Ok(invalid_grant(
            "no service principal has this workload identity",
        ));
    };
    let principal = konklav_store::subjects::get(conn, credential.subject_id).await?;
    if principal.kind != konklav_store::subjects::SubjectKind::Service
        || principal.state != konklav_store::subjects::SubjectState::Active
    {
        return Ok(invalid_grant(
            "no service principal has this workload identity",
        ));
    }
    // Each assertion is exchanged once; a second exchange means it leaked.
    // r[impl federation.jwt-bearer.replay]
    let expires = chrono::DateTime::from_timestamp(verified.exp, 0).unwrap_or_else(Utc::now);
    if !konklav_store::bearer_assertions::record(
        conn,
        &provider.settings.issuer,
        &verified.jti,
        expires,
    )
    .await?
    {
        return Ok(invalid_grant("the assertion was already used"));
    }
    let now = Utc::now();
    let (session, _) = sessions::insert(
        conn,
        NewSession {
            dpop_jkt: dpop_jkt.map(str::to_owned),
            id: SessionId::new_v7(),
            subject_id: credential.subject_id,
            credential_id: credential.id,
            stage: Stage::Identity,
            client_kind: SessionClient::Native,
            amr: vec![crate::federation::FEDERATED_METHOD.to_owned()],
            auth_time: now,
            flags: Vec::new(),
            impersonator_subject_id: None,
            parent_session_id: None,
            // Never presented: these sessions can't be refreshed.
            refresh_hash: Sha256::digest(generate_secret().as_bytes()).to_vec(),
            expires_at: now + state.auth.access_ttl,
        },
    )
    .await?;
    let access = issue::access_token(conn, &state.auth, &session).await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "access_token": access.access_token,
            "token_type": token_type(&session),
            "expires_in": access.expires_in,
        })),
    )
        .into_response())
}

// --- Peering -------------------------------------------------------------------

#[derive(Serialize)]
struct PeerEvent {
    cursor: i64,
    kind: &'static str,
    /// The subject affected; absent when every subject may be.
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<konklav_core::SubjectId>,
}

/// `POST /v1/oauth2/peer/events`: the client's view of the change feed.
/// Only subjects that have had a session for the client appear, so a client
/// learns nothing about anyone else.
// r[impl federation.peer.feed]
async fn peer_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Response, ApiError> {
    provider(&state)?;
    let mut conn = state.pool.get().await?;
    let Some(client) = authenticate_peer(&state, &mut conn, &headers, &form).await else {
        return Ok(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        ));
    };
    let after = form.after.unwrap_or(0);
    let scanned =
        konklav_store::events::after(&mut conn, konklav_core::Cursor::new(after), 500).await?;
    let next = scanned.last().map_or(after, |event| event.cursor);
    let mut candidates: Vec<(i64, &'static str, Option<konklav_core::SubjectId>)> = Vec::new();
    for event in &scanned {
        let parse = |value: &serde_json::Value| {
            value
                .as_str()
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
                .map(konklav_core::SubjectId::from)
        };
        match event.kind.as_str() {
            "subject.changed" => {
                if let Some(subject) = parse(&event.payload["subject"]) {
                    candidates.push((event.cursor, "subject.changed", Some(subject)));
                }
            }
            "entitlements.changed" if event.payload["all"] == true => {
                candidates.push((event.cursor, "entitlements.changed", None));
            }
            "entitlements.changed" => {
                for subject in event.payload["subjects"].as_array().into_iter().flatten() {
                    if let Some(subject) = parse(subject) {
                        candidates.push((event.cursor, "entitlements.changed", Some(subject)));
                    }
                }
            }
            _ => {}
        }
    }
    let named: Vec<_> = candidates.iter().filter_map(|(_, _, s)| *s).collect();
    let known = sessions::subjects_with_client(&mut conn, &client.id, &named).await?;
    let events: Vec<PeerEvent> = candidates
        .into_iter()
        .filter(|(_, _, subject)| subject.is_none_or(|s| known.contains(&s)))
        .map(|(cursor, kind, subject)| PeerEvent {
            cursor,
            kind,
            subject,
        })
        .collect();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"events": events, "next": next})),
    )
        .into_response())
}

/// Authenticates a client for the peer endpoints. A public client proves
/// nothing beyond its id, which anyone can know, so only confidential
/// clients may read subjects through them.
// r[impl federation.peer.feed]
async fn authenticate_peer(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
    form: &TokenRequest,
) -> Option<OidcClient> {
    authenticate_client(state, conn, headers, form)
        .await
        .filter(|client| client.kind == ClientKind::Confidential)
}

/// `POST /v1/oauth2/peer/subjects`: whether a subject is still active, and
/// the claims the client would receive for it with all its scopes. Only
/// for subjects that have had a session for the client.
async fn peer_subject(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Response, ApiError> {
    provider(&state)?;
    let mut conn = state.pool.get().await?;
    let Some(client) = authenticate_peer(&state, &mut conn, &headers, &form).await else {
        return Ok(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        ));
    };
    let unknown = || {
        oauth_error(
            StatusCode::NOT_FOUND,
            "unknown_subject",
            "no such subject has signed in to this client",
        )
    };
    let Some(subject) = form
        .subject
        .as_deref()
        .and_then(|s| s.parse::<uuid::Uuid>().ok())
        .map(konklav_core::SubjectId::from)
    else {
        return Ok(unknown());
    };
    let Some(latest) = sessions::latest_for_client(&mut conn, &client.id, subject).await? else {
        return Ok(unknown());
    };
    let principal = konklav_store::subjects::get(&mut conn, subject).await?;
    let credential = credentials::get(&mut conn, latest.credential_id).await?;
    let selection = Selection {
        scopes: &client.scopes,
        claims: &[],
    };
    let claims = oidc::claims(&mut conn, &client, selection, subject, &credential).await?;
    drop(conn);
    let mut body = serde_json::to_value(&claims).map_err(ApiError::internal)?;
    body["sub"] = serde_json::json!(subject);
    body["active"] =
        serde_json::json!(principal.state == konklav_store::subjects::SubjectState::Active);
    add_hook_claims(
        &state,
        &mut body,
        &ClaimsFor {
            subject,
            client: &client.id,
            tenant: latest.tenant_id,
            membership: latest.membership_id,
            granted: &client.scopes,
            requested: &[],
        },
    )
    .await?;
    add_passed_claims(
        &mut body,
        latest.identity_claims.as_ref(),
        &client.scopes,
        &[],
    );
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response())
}

// --- Userinfo -------------------------------------------------------------------

/// `GET` or `POST /v1/oauth2/userinfo`, with an access token issued to a
/// client.
#[derive(Deserialize)]
struct UserinfoForm {
    access_token: Option<String>,
}

/// `GET /v1/oauth2/userinfo`
async fn userinfo_get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    challenged(userinfo(&state, "GET", &headers, None).await)
}

/// `POST /v1/oauth2/userinfo`, with the access token in the header or the
/// form body.
async fn userinfo_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<UserinfoForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let body_token = form.ok().and_then(|Form(form)| form.access_token);
    challenged(userinfo(&state, "POST", &headers, body_token.as_deref()).await)
}

/// Why userinfo refused a request.
enum UserinfoRefusal {
    Api(ApiError),
    /// Refused for the DPoP proof or the authorization scheme.
    Dpop(&'static str),
}

impl From<ApiError> for UserinfoRefusal {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

/// A 401 carries a bearer challenge (RFC 6750 3), offering DPoP too; a
/// refusal for the DPoP proof carries a DPoP challenge (RFC 9449 7.1).
// r[impl oidc.provider.userinfo]
fn challenged(result: Result<Response, UserinfoRefusal>) -> Response {
    match result {
        Ok(response) => response,
        Err(UserinfoRefusal::Dpop(reason)) => dpop::invalid_resource_request(reason),
        Err(UserinfoRefusal::Api(error)) => {
            let mut response = error.into_response();
            if response.status() == StatusCode::UNAUTHORIZED {
                let headers = response.headers_mut();
                headers.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_token\""),
                );
                headers.append(header::WWW_AUTHENTICATE, dpop::challenge());
            }
            response
        }
    }
}

/// How the access token came: which authorization scheme, or the form.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Bearer,
    Dpop,
}

/// The access token and its scheme, from the `Authorization` header or,
/// as a bearer token, the form body.
fn presented_token<'a>(
    headers: &'a HeaderMap,
    body_token: Option<&'a str>,
) -> Option<(&'a str, Scheme)> {
    let from_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .and_then(|(scheme, token)| {
            if scheme.eq_ignore_ascii_case("Bearer") {
                Some((token, Scheme::Bearer))
            } else if scheme.eq_ignore_ascii_case("DPoP") {
                Some((token, Scheme::Dpop))
            } else {
                None
            }
        });
    from_header.or(body_token.map(|token| (token, Scheme::Bearer)))
}

async fn userinfo(
    state: &AppState,
    method: &str,
    headers: &HeaderMap,
    body_token: Option<&str>,
) -> Result<Response, UserinfoRefusal> {
    provider(state)?;
    let mut conn = state.pool.get().await.map_err(ApiError::from)?;
    let unauthenticated = || {
        ApiError::new(
            ErrorCode::Unauthenticated,
            "missing or invalid access token",
        )
    };
    let (token, scheme) = presented_token(headers, body_token).ok_or_else(unauthenticated)?;
    // Only tokens issued to a client, checked against that client's audience.
    let claimed = konklav_token::decode_claims_unverified(token).ok_or_else(unauthenticated)?;
    let client_id = sessions::get(&mut conn, claimed.sid)
        .await
        .ok()
        .and_then(|session| session.oidc_client_id)
        .ok_or_else(unauthenticated)?;
    let client = oidc_clients::get(&mut conn, &client_id)
        .await
        .map_err(ApiError::from)?;
    let (verified, session) =
        subject_api::verify_access_token_for(state, &mut conn, token, &client.audience).await?;
    // r[impl token.dpop.scheme]
    match (&verified.cnf, scheme) {
        (Some(cnf), Scheme::Dpop) => {
            let expected = dpop::Expected {
                method,
                urls: dpop::Expected::endpoint(state, "userinfo"),
                access_token: Some(token),
                bound_to: Some(&cnf.jkt),
            };
            match dpop::check(state, &mut conn, headers, &expected).await? {
                Ok(Some(_)) => {}
                Ok(None) => return Err(UserinfoRefusal::Dpop("a DPoP proof is required")),
                Err(reason) => return Err(UserinfoRefusal::Dpop(reason)),
            }
        }
        (Some(_), Scheme::Bearer) => {
            return Err(UserinfoRefusal::Dpop(
                "the access token is DPoP-bound; use the DPoP scheme",
            ));
        }
        (None, Scheme::Dpop) => {
            return Err(UserinfoRefusal::Dpop("the access token isn't DPoP-bound"));
        }
        (None, Scheme::Bearer) => {}
    }
    let credential = credentials::get(&mut conn, session.credential_id)
        .await
        .map_err(ApiError::from)?;
    let selection = Selection {
        scopes: &session.oidc_scopes,
        claims: &session.oidc_claims.userinfo,
    };
    let claims = oidc::claims(
        &mut conn,
        &client,
        selection,
        session.subject_id,
        &credential,
    )
    .await?;
    drop(conn);
    let mut body = serde_json::to_value(&claims).map_err(ApiError::internal)?;
    body["sub"] = serde_json::json!(session.subject_id);
    add_hook_claims(
        state,
        &mut body,
        &ClaimsFor {
            subject: session.subject_id,
            client: &client.id,
            tenant: session.tenant_id,
            membership: session.membership_id,
            granted: &session.oidc_scopes,
            requested: &session.oidc_claims.userinfo,
        },
    )
    .await?;
    add_passed_claims(
        &mut body,
        session.identity_claims.as_ref(),
        &session.oidc_scopes,
        &session.oidc_claims.userinfo,
    );
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response())
}

/// Adds the claims passed from an identity provider for granted scopes and
/// requested claims to `body`, never replacing Konklav's or the hook's.
// r[impl federation.pass-claims]
fn add_passed_claims(
    body: &mut serde_json::Value,
    passed: Option<&serde_json::Value>,
    scopes: &[String],
    requested: &[String],
) {
    let (Some(serde_json::Value::Object(passed)), serde_json::Value::Object(body)) = (passed, body)
    else {
        return;
    };
    for (scope, claims) in passed {
        let granted = scopes.contains(scope);
        let serde_json::Value::Object(claims) = claims else {
            continue;
        };
        for (name, value) in claims {
            if granted || requested.contains(name) {
                body.entry(name.clone()).or_insert_with(|| value.clone());
            }
        }
    }
}

/// Adds the claims hook's claims to `body`, never replacing Konklav's own.
async fn add_hook_claims(
    state: &AppState,
    body: &mut serde_json::Value,
    request: &ClaimsFor<'_>,
) -> Result<(), ApiError> {
    let provider = provider(state)?;
    let Some(hook) = &provider.claims_hook else {
        return Ok(());
    };
    let claims = hook.fetch(provider, &state.auth.issuer, request).await?;
    if let serde_json::Value::Object(body) = body {
        for (name, value) in claims {
            body.entry(name).or_insert(value);
        }
    }
    Ok(())
}
