//! The admin page, on <http://localhost:4000>: frontend and backend in one.
//!
//! A backend-for-frontend. It is a confidential OIDC client (`admin`): it
//! signs people in through Konklav with the code flow, PKCE and DPoP, and
//! keeps the tokens and the DPoP key in this process. The browser gets an
//! opaque, `HttpOnly` session cookie; no token ever reaches it.
//!
//! Every API request is decided by the relying client: the backend presents
//! the admin's DPoP token with a proof from its own key, and the request
//! goes through only if the person holds `admin:access`. A role taken away,
//! or a session ended anywhere, is refused within about a second.
//!
//! What admins do goes through the control-plane surface as the
//! `admin-api` service principal, which may manage people, roles and
//! sessions and nothing else.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use konklav_authz::{Decision, DenyReason, Requirements};
use konklav_core::Cursor;
use konklav_relying_client::{Presented, RelyingClient, RequestDescriptor};
use konklav_sso_example::dpop::DpopKey;
use konklav_sso_example::web::{self, ADMIN_HTML, ADMIN_JS};
use konklav_sso_example::{claims_of, env, random_token, relying_client, secrets, serve};
use konklav_token::TokenKind;
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const CLIENT_ID: &str = "admin";
const MANAGED_ROLES: [&str; 3] = ["member", "editor", "admin"];
// Cookies on localhost are shared by every port, so the names are specific.
const SESSION_COOKIE: &str = "example_admin_session";
const LOGIN_COOKIE: &str = "example_admin_login";
/// Sent by the page's scripts on every write. Another site can't send it
/// without a CORS preflight, which this origin never answers.
const CSRF_HEADER: &str = "x-example-admin";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

// --- State -------------------------------------------------------------------

/// Konklav's public endpoints, from discovery.
#[derive(Deserialize)]
#[expect(clippy::struct_field_names, reason = "named as discovery names them")]
struct Endpoints {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    end_session_endpoint: String,
}

struct Tokens {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Instant,
}

/// One signed-in admin. Lives in this process only, so a restart signs
/// everyone out of the admin page (but not of the login page).
struct Session {
    key: DpopKey,
    tokens: tokio::sync::Mutex<Tokens>,
    id_token: String,
    sub: String,
    email: String,
}

struct PendingLogin {
    key: DpopKey,
    verifier: String,
    nonce: String,
    created: Instant,
}

struct Admin {
    http: reqwest::Client,
    issuer: String,
    subject_url: String,
    public_url: String,
    client_secret: String,
    endpoints: Endpoints,
    relying: RelyingClient,
    control: ControlPlane,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    pending: Mutex<HashMap<String, PendingLogin>>,
}

impl Admin {
    /// Konklav's public endpoint URLs, as this container reaches them. The
    /// proofs keep naming the public URL, which is what Konklav checks.
    fn internal(&self, url: &str) -> String {
        url.replacen(&self.issuer, &self.subject_url, 1)
    }
}

/// A refusal, answered as JSON.
struct Refused(StatusCode, String);

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"message": self.1}))).into_response()
    }
}

impl From<reqwest::Error> for Refused {
    fn from(error: reqwest::Error) -> Self {
        Self(
            StatusCode::BAD_GATEWAY,
            format!("Konklav is unreachable: {error}"),
        )
    }
}

type Answer = Result<Response, Refused>;

fn refused(status: StatusCode, message: impl Into<String>) -> Refused {
    Refused(status, message.into())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            pair.trim()
                .strip_prefix(name)?
                .strip_prefix('=')
                .map(str::to_owned)
        })
}

fn set_cookie(response: &mut Response, value: &str) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(value).expect("a valid cookie"),
    );
}

// --- The control plane -------------------------------------------------------

/// The control-plane surface, as the `admin-api` service principal.
struct ControlPlane {
    http: reqwest::Client,
    url: String,
    subject_url: String,
    key_id: String,
    secret: String,
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl ControlPlane {
    /// The service principal's access token, logging in again at 80% of
    /// its lifetime.
    async fn token(&self) -> Result<String, Refused> {
        let mut token = self.token.lock().await;
        if let Some((value, renew_at)) = token.as_ref()
            && Instant::now() < *renew_at
        {
            return Ok(value.clone());
        }
        let body: Value = self
            .http
            .post(format!("{}/v1/login/secret-key", self.subject_url))
            .json(&json!({"key_id": self.key_id, "secret": self.secret}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let value = body["access_token"].as_str().unwrap_or_default().to_owned();
        let lifetime = body["expires_in"].as_u64().unwrap_or(60);
        *token = Some((
            value.clone(),
            Instant::now() + Duration::from_secs(lifetime * 4 / 5),
        ));
        Ok(value)
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, Refused> {
        let mut request = self
            .http
            .request(method, format!("{}/v1{path}", self.url))
            .bearer_auth(self.token().await?);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(body);
        }
        // Konklav's errors are {"error": {"code": …, "message": …}}.
        let message = body["error"]["message"]
            .as_str()
            .unwrap_or("the control plane refused");
        Err(refused(status, message))
    }

    async fn get(&self, path: &str) -> Result<Value, Refused> {
        self.call(Method::GET, path, None).await
    }

    async fn role_keys(&self) -> Result<HashMap<String, String>, Refused> {
        let roles = self.get("/tenants/root/roles").await?;
        Ok(roles
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|role| {
                Some((
                    role["id"].as_str()?.to_owned(),
                    role["key"].as_str()?.to_owned(),
                ))
            })
            .collect())
    }
}

/// Waits until the relying client has seen a write, so the next decision
/// reflects it (read-your-writes).
async fn settled(admin: &Admin, written: &Value) {
    if let Ok(cursor) = serde_json::from_value::<Cursor>(written["cursor"].clone()) {
        admin
            .relying
            .await_cursor(cursor, Duration::from_secs(5))
            .await;
    }
}

// --- Tokens ------------------------------------------------------------------

/// A token request authenticated with the client secret and carrying a
/// proof of `key`, so the tokens are bound to it.
async fn token_request(
    admin: &Admin,
    key: &DpopKey,
    params: &[(&str, &str)],
) -> Result<Value, Refused> {
    let endpoint = &admin.endpoints.token_endpoint;
    let response = admin
        .http
        .post(admin.internal(endpoint))
        .basic_auth(CLIENT_ID, Some(&admin.client_secret))
        .header("dpop", key.proof("POST", endpoint, None))
        .form(params)
        .send()
        .await?;
    let ok = response.status().is_success();
    let body: Value = response.json().await?;
    if !ok {
        let message = body["error_description"]
            .as_str()
            .or(body["error"].as_str())
            .unwrap_or("token request failed");
        return Err(refused(StatusCode::UNAUTHORIZED, message));
    }
    if body["token_type"] != "DPoP" {
        return Err(refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            "expected DPoP tokens",
        ));
    }
    Ok(body)
}

fn tokens_from(body: &Value, previous_refresh: Option<String>) -> Tokens {
    Tokens {
        access_token: body["access_token"].as_str().unwrap_or_default().to_owned(),
        refresh_token: body["refresh_token"]
            .as_str()
            .map(str::to_owned)
            .or(previous_refresh),
        expires_at: Instant::now() + Duration::from_secs(body["expires_in"].as_u64().unwrap_or(0)),
    }
}

/// The session's access token, refreshed with its key when about to expire.
async fn fresh_token(admin: &Admin, session: &Session) -> Result<String, Refused> {
    let mut tokens = session.tokens.lock().await;
    if tokens.expires_at > Instant::now() + Duration::from_secs(30) {
        return Ok(tokens.access_token.clone());
    }
    let Some(refresh) = tokens.refresh_token.clone() else {
        return Err(refused(
            StatusCode::UNAUTHORIZED,
            "your sign-in has expired",
        ));
    };
    let body = token_request(
        admin,
        &session.key,
        &[("grant_type", "refresh_token"), ("refresh_token", &refresh)],
    )
    .await?;
    *tokens = tokens_from(&body, Some(refresh));
    Ok(tokens.access_token.clone())
}

/// The request's session, and whether its person may use the admin page.
///
/// The decision comes from the relying client, with the session's token
/// under the `DPoP` scheme and a proof for this request signed by the
/// session's key. The browser never sees either.
/// The parts of the request it needs: a `Request` itself isn't `Sync`.
struct Asked {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Asked {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            headers: parts.headers.clone(),
        }))
    }
}

async fn authorize(
    admin: &Admin,
    request: &Asked,
    require_admin: bool,
) -> Result<(Arc<Session>, bool), Refused> {
    let headers = &request.headers;
    if request.method != Method::GET {
        let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
        if !headers.contains_key(CSRF_HEADER) || origin != Some(admin.public_url.as_str()) {
            return Err(refused(StatusCode::FORBIDDEN, "cross-site request refused"));
        }
    }
    let sid = cookie(headers, SESSION_COOKIE).unwrap_or_default();
    let session = admin.sessions.lock().expect("sessions").get(&sid).cloned();
    let Some(session) = session else {
        return Err(refused(StatusCode::UNAUTHORIZED, "sign in first"));
    };
    let forget = || admin.sessions.lock().expect("sessions").remove(&sid);
    let token = match fresh_token(admin, &session).await {
        Ok(token) => token,
        Err(error) => {
            forget();
            return Err(error);
        }
    };
    let method = request.method.as_str();
    let url = format!("{}{}", admin.public_url, request.uri.path());
    let presented = Presented {
        authorization: format!("DPoP {token}"),
        dpop: Some(session.key.proof(method, &url, Some(&token))),
        request: Some(RequestDescriptor {
            method: method.into(),
            url,
        }),
    };
    let requirements = Requirements {
        global: BTreeSet::from(["admin:access".to_owned()]),
        token_kinds: Some(BTreeSet::from([TokenKind::Identity])),
        ..Requirements::default()
    };
    let decision = admin
        .relying
        .decide_request(&presented, &requirements)
        .await
        .map_err(|_| {
            refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization is unavailable; try again",
            )
        })?;
    if decision
        == (Decision::Deny {
            reason: DenyReason::InvalidToken,
        })
    {
        // Revoked: signed out at the login page or the app, or by an admin.
        forget();
        return Err(refused(StatusCode::UNAUTHORIZED, "your session has ended"));
    }
    let allowed = matches!(decision, Decision::Allow { .. });
    if require_admin && !allowed {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "you need the admin role to use this page",
        ));
    }
    Ok((session, allowed))
}

// --- Signing in and out ------------------------------------------------------

/// Starts a sign-in. With `?silent`, asks for `prompt=none`: single sign-on
/// when the person is signed in at the login page, `login_required` if not.
async fn login(
    State(admin): State<Arc<Admin>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let state = random_token(16);
    let pending = PendingLogin {
        key: DpopKey::new(),
        verifier: random_token(32),
        nonce: random_token(16),
        created: Instant::now(),
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
    let redirect_uri = format!("{}/callback", admin.public_url);
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", redirect_uri.as_str()),
        ("scope", "openid email"),
        ("state", state.as_str()),
        ("nonce", pending.nonce.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    // Binds the code to the key, as for the token request.
    let jkt = pending.key.thumbprint();
    params.push(("dpop_jkt", &jkt));
    if query.contains_key("silent") {
        params.push(("prompt", "none"));
    }
    let url =
        Url::parse_with_params(&admin.endpoints.authorization_endpoint, &params).expect("a URL");
    {
        let mut logins = admin.pending.lock().expect("pending");
        // Forget logins that were never finished.
        logins.retain(|_, login| login.created.elapsed() < Duration::from_secs(600));
        logins.insert(state.clone(), pending);
    }
    let mut response = Redirect::to(url.as_str()).into_response();
    // Ties the callback to the browser that started the login.
    set_cookie(
        &mut response,
        &format!("{LOGIN_COOKIE}={state}; Max-Age=600; Path=/callback; HttpOnly; SameSite=Lax"),
    );
    response
}

async fn callback(
    State(admin): State<Arc<Admin>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Answer {
    let param = |name: &str| query.get(name).map_or("", String::as_str);
    let state = param("state");
    let pending = admin.pending.lock().expect("pending").remove(state);
    let Some(pending) =
        pending.filter(|_| cookie(&headers, LOGIN_COOKIE).as_deref() == Some(state))
    else {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "this sign-in wasn't started in this browser",
        ));
    };
    if param("iss") != admin.issuer {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "the response came from another issuer",
        ));
    }
    if let Some(error) = query.get("error") {
        return Ok(Redirect::to(&format!("/?error={error}")).into_response());
    }

    let redirect_uri = format!("{}/callback", admin.public_url);
    let body = token_request(
        &admin,
        &pending.key,
        &[
            ("grant_type", "authorization_code"),
            ("code", param("code")),
            ("redirect_uri", &redirect_uri),
            ("code_verifier", &pending.verifier),
        ],
    )
    .await?;
    // Straight from the token endpoint over a connection this server made,
    // so its signature needs no further check (OIDC Core 3.1.3.7).
    let id_token = body["id_token"].as_str().unwrap_or_default().to_owned();
    let identity = claims_of(&id_token).unwrap_or_default();
    let audience_ok = identity["aud"] == CLIENT_ID || identity["aud"] == json!([CLIENT_ID]);
    if identity["nonce"] != pending.nonce.as_str() || !audience_ok {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "the ID token doesn't match this sign-in",
        ));
    }
    let tokens = tokens_from(&body, None);
    let sub = identity["sub"].as_str().unwrap_or_default().to_owned();

    let userinfo_url = &admin.endpoints.userinfo_endpoint;
    let userinfo: Value = admin
        .http
        .get(admin.internal(userinfo_url))
        .header(
            header::AUTHORIZATION,
            format!("DPoP {}", tokens.access_token),
        )
        .header(
            "dpop",
            pending
                .key
                .proof("GET", userinfo_url, Some(&tokens.access_token)),
        )
        .send()
        .await?
        .json()
        .await
        .unwrap_or_default();
    let email = userinfo["email"].as_str().unwrap_or(&sub).to_owned();

    let sid = random_token(32);
    let session = Session {
        key: pending.key,
        tokens: tokio::sync::Mutex::new(tokens),
        id_token,
        sub,
        email,
    };
    admin
        .sessions
        .lock()
        .expect("sessions")
        .insert(sid.clone(), Arc::new(session));
    let mut response = Redirect::to("/").into_response();
    set_cookie(
        &mut response,
        &format!("{LOGIN_COOKIE}=; Max-Age=0; Path=/callback"),
    );
    set_cookie(
        &mut response,
        &format!("{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict"),
    );
    Ok(response)
}

async fn logout(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Answer {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !headers.contains_key(CSRF_HEADER) || origin != Some(admin.public_url.as_str()) {
        return Err(refused(StatusCode::FORBIDDEN, "cross-site request refused"));
    }
    let sid = cookie(&headers, SESSION_COOKIE).unwrap_or_default();
    let session = admin.sessions.lock().expect("sessions").remove(&sid);
    let redirect = match session {
        // Ends the sign-in at the login page too, and the app's session.
        Some(session) => Url::parse_with_params(
            &admin.endpoints.end_session_endpoint,
            &[
                ("client_id", CLIENT_ID),
                ("id_token_hint", session.id_token.as_str()),
                (
                    "post_logout_redirect_uri",
                    &format!("{}/", admin.public_url),
                ),
            ],
        )
        .expect("a URL")
        .to_string(),
        None => "/".into(),
    };
    let mut response = Json(json!({"redirect": redirect})).into_response();
    set_cookie(
        &mut response,
        &format!("{SESSION_COOKIE}=; Max-Age=0; Path=/"),
    );
    Ok(response)
}

// --- The admin API -----------------------------------------------------------

async fn me(State(admin): State<Arc<Admin>>, request: Asked) -> Answer {
    let (session, allowed) = authorize(&admin, &request, false).await?;
    Ok(Json(json!({"sub": session.sub, "email": session.email, "admin": allowed})).into_response())
}

async fn list_users(State(admin): State<Arc<Admin>>, request: Asked) -> Answer {
    authorize(&admin, &request, true).await?;
    let control = &admin.control;
    let keys = control.role_keys().await?;
    let mut users = Vec::new();
    let mut before: Option<String> = None;
    loop {
        let page_path = match &before {
            Some(id) => format!("/subjects?kind=human&before={id}"),
            None => "/subjects?kind=human".into(),
        };
        let page = control.get(&page_path).await?;
        for subject in page["subjects"].as_array().into_iter().flatten() {
            let id = subject["id"].as_str().unwrap_or_default();
            let (detail_path, assignments_path) = (
                format!("/subjects/{id}"),
                format!("/subjects/{id}/global-assignments"),
            );
            let (detail, assignments) =
                tokio::try_join!(control.get(&detail_path), control.get(&assignments_path))?;
            let emails: Vec<&str> = detail["credentials"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|c| c["kind"] == "password" && c["revoked_at"].is_null())
                .filter_map(|c| c["identifier"].as_str())
                .collect();
            let mut roles: Vec<&str> = assignments
                .as_array()
                .into_iter()
                .flatten()
                .map(|a| {
                    a["role_id"]
                        .as_str()
                        .and_then(|r| keys.get(r))
                        .map_or("?", String::as_str)
                })
                .collect();
            roles.sort_unstable();
            users.push(
                json!({"id": id, "state": subject["state"], "emails": emails, "roles": roles}),
            );
        }
        match page["next"].as_str() {
            Some(next) => before = Some(next.to_owned()),
            None => break,
        }
    }
    users.sort_by_key(|user| user["emails"][0].as_str().unwrap_or_default().to_owned());
    Ok(Json(json!({"users": users, "roles": MANAGED_ROLES})).into_response())
}

async fn create_user(
    State(admin): State<Arc<Admin>>,
    request: Asked,
    Json(body): Json<Value>,
) -> Answer {
    authorize(&admin, &request, true).await?;
    let email = body["email"].as_str().unwrap_or_default().trim();
    let password = body["password"].as_str().unwrap_or_default();
    if email.is_empty() || password.chars().count() < 12 {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "give an email and a password of at least 12 characters",
        ));
    }
    let control = &admin.control;
    let subject = uuid::Uuid::new_v4().to_string();
    control
        .call(
            Method::PUT,
            &format!("/subjects/{subject}"),
            Some(json!({"kind": "human"})),
        )
        .await?;
    control
        .call(
            Method::POST,
            &format!("/subjects/{subject}/credentials"),
            Some(json!({"kind": "password", "identifier": email, "password": password})),
        )
        .await?;
    let written = control
        .call(
            Method::POST,
            &format!("/subjects/{subject}/global-assignments"),
            Some(json!({"role": "member"})),
        )
        .await?;
    settled(&admin, &written).await;
    Ok((StatusCode::CREATED, Json(json!({"id": subject}))).into_response())
}

async fn set_role(
    State(admin): State<Arc<Admin>>,
    Path((subject, role)): Path<(String, String)>,
    request: Asked,
) -> Answer {
    let (session, _) = authorize(&admin, &request, true).await?;
    if !MANAGED_ROLES.contains(&role.as_str()) {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            format!("this page manages only {}", MANAGED_ROLES.join(", ")),
        ));
    }
    let control = &admin.control;
    if request.method == Method::PUT {
        let written = control
            .call(
                Method::POST,
                &format!("/subjects/{subject}/global-assignments"),
                Some(json!({"role": role})),
            )
            .await?;
        settled(&admin, &written).await;
        return Ok(Json(json!({"ok": true})).into_response());
    }
    if subject == session.sub && role == "admin" {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "you can't take away your own admin role",
        ));
    }
    let keys = control.role_keys().await?;
    let assignments = control
        .get(&format!("/subjects/{subject}/global-assignments"))
        .await?;
    for assignment in assignments.as_array().into_iter().flatten() {
        if assignment["role_id"].as_str().and_then(|id| keys.get(id)) == Some(&role)
            && let Some(id) = assignment["id"].as_str()
        {
            let written = control
                .call(Method::DELETE, &format!("/assignments/{id}"), None)
                .await?;
            settled(&admin, &written).await;
        }
    }
    Ok(Json(json!({"ok": true})).into_response())
}

/// `sign-out` (every session), `disable` or `enable`.
async fn act_on_user(
    State(admin): State<Arc<Admin>>,
    Path((subject, action)): Path<(String, String)>,
    request: Asked,
) -> Answer {
    let (session, _) = authorize(&admin, &request, true).await?;
    let control = &admin.control;
    let written = match action.as_str() {
        "sign-out" => {
            control
                .call(
                    Method::POST,
                    "/sessions/revoke",
                    Some(json!({"subject": subject, "reason": "signed out by an admin"})),
                )
                .await?
        }
        "disable" if subject == session.sub => {
            return Err(refused(
                StatusCode::BAD_REQUEST,
                "you can't disable yourself",
            ));
        }
        "disable" | "enable" => {
            control
                .call(Method::POST, &format!("/subjects/{subject}/{action}"), None)
                .await?
        }
        _ => return Err(refused(StatusCode::NOT_FOUND, "not found")),
    };
    settled(&admin, &written).await;
    Ok(Json(json!({"ok": true, "you": subject == session.sub})).into_response())
}

// --- Serving -----------------------------------------------------------------

#[tokio::main]
async fn main() {
    let secrets = secrets();
    let subject_url = env("KONKLAV_SUBJECT_URL");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("an HTTP client");
    let endpoints: Endpoints = http
        .get(format!("{subject_url}/.well-known/openid-configuration"))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .expect("Konklav's discovery document")
        .json()
        .await
        .expect("a discovery document");
    // One service principal for both: following the feed, and the control plane.
    let (key_id, secret) = secrets
        .admin_api_key
        .split_once('.')
        .expect("<key id>.<secret>");
    let admin = Arc::new(Admin {
        control: ControlPlane {
            http: http.clone(),
            url: env("KONKLAV_CONTROL_URL"),
            subject_url: subject_url.clone(),
            key_id: key_id.into(),
            secret: secret.into(),
            token: tokio::sync::Mutex::new(None),
        },
        // The `admin` OIDC client's tokens carry this audience.
        relying: relying_client("admin", &secrets.admin_api_key).await,
        http,
        issuer: env("ISSUER"),
        subject_url,
        public_url: env("PUBLIC_URL"),
        client_secret: secrets.admin_client_secret.clone(),
        endpoints,
        sessions: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
    });

    let router = Router::new()
        .route("/", get(|| async { web::page(ADMIN_HTML, CSP) }))
        .route("/static/admin.js", get(|| async { web::script(ADMIN_JS) }))
        .merge(web::shared())
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/users", get(list_users).post(create_user))
        .route(
            "/api/users/{subject}/roles/{role}",
            put(set_role).delete(set_role),
        )
        .route("/api/users/{subject}/{action}", post(act_on_user))
        .with_state(admin);
    serve(router, 4000).await;
}
