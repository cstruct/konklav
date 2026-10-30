//! Konklav set up for the OpenID conformance suite: an OpenID provider, the
//! suite's static clients, and a login page its browser can drive.
//!
//! Konklav hands sign-in to a login application, so the suite needs one.
//! This one signs a fixed test user in when its button is pressed, and
//! remembers the sign-in in a cookie of its own, so `prompt=none` can be
//! answered without asking. Without one, it refuses `prompt=none` with
//! `login_required`. When a remembered sign-in doesn't satisfy a request
//! (an old `max_age`, or `prompt=login`), it asks again.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use reqwest::Method;
use serde_json::{Value, json};

use crate::harness::{Server, Setup};
use crate::{Result, fail};

/// The test user the login page signs in.
pub const EMAIL: &str = "conformance@example.com";
const PHONE: &str = "+46700000000";
const COOKIE: &str = "conformance_login";

/// A provider ready for the suite, with the config to give it.
pub struct Conformance {
    pub konklav: Server,
    /// The suite's test plan configuration.
    pub config: Value,
}

struct LoginPage {
    /// Konklav's subject-facing surface, as this process reaches it.
    konklav: String,
    origin: String,
    password: String,
    http: reqwest::Client,
    /// Access tokens of remembered sign-ins, by cookie value.
    remembered: Mutex<HashMap<String, String>>,
}

/// Starts Konklav and the login page. `host` is how the suite's containers
/// reach this machine, such as `host.docker.internal`; `suite` is the
/// suite's base URL, and `alias` the alias its callback URLs use.
/// With `issuer`, Konklav's issuer is that URL instead, for a proxy that
/// terminates TLS in front of it.
pub async fn start(
    binary: &Path,
    host: &str,
    issuer: Option<String>,
    suite: &str,
    alias: &str,
) -> Result<Conformance> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{host}:{}", listener.local_addr()?.port());
    let konklav = Server::start(&Setup {
        binary: Some(binary.to_owned()),
        issuer_host: Some(host.to_owned()),
        issuer,
        login_url: Some(format!("{origin}/sign-in")),
        browser_origins: vec![origin.clone()],
        ..Setup::default()
    })
    .await?;
    let password = format!("conformance-{}", uuid::Uuid::now_v7().simple());
    let user = konklav
        .human(json!({"kind": "password", "identifier": EMAIL, "password": password}))
        .await?;
    // For the `phone` scope's claims.
    konklav
        .control(
            Method::POST,
            &format!("/v1/subjects/{user}/credentials"),
            Some(json!({"kind": "phone_otp", "identifier": PHONE})),
        )
        .await?;

    let callback = format!("{}/test/a/{alias}/callback", suite.trim_end_matches('/'));
    let mut clients = Vec::new();
    // One client gets RS256 ID tokens, the other ES256.
    for (id, alg) in [("conformance-1", "RS256"), ("conformance-2", "ES256")] {
        konklav
            .control(
                Method::PUT,
                &format!("/v1/oidc/clients/{id}"),
                Some(json!({
                    "kind": "confidential",
                    "redirect_uris": [callback, format!("{callback}?dummy1=lorem&dummy2=ipsum")],
                    "scopes": ["openid", "email", "phone"],
                    "audience": id,
                    "id_token_alg": alg,
                    // The suite's Basic OP plan sends no PKCE.
                    "require_pkce": false,
                })),
            )
            .await?;
        let secret = konklav
            .control(Method::POST, &format!("/v1/oidc/clients/{id}/secret"), None)
            .await?["client_secret"]
            .as_str()
            .ok_or_else(|| fail("no client secret"))?
            .to_owned();
        clients.push(json!({"client_id": id, "client_secret": secret}));
    }

    let page = Arc::new(LoginPage {
        konklav: konklav.subject.clone(),
        origin: origin.clone(),
        password,
        http: reqwest::Client::new(),
        remembered: Mutex::new(HashMap::new()),
    });
    let router = Router::new()
        .route("/sign-in", get(show).post(sign_in))
        .with_state(page);
    tokio::spawn(async move { axum::serve(listener, router).await });

    let config = config(&konklav.issuer, &origin, alias, &clients);
    Ok(Conformance { konklav, config })
}

/// The suite's configuration: where Konklav is, the clients, and how its
/// browser signs in. Tests that need a screenshot as evidence, of a second
/// sign-in or of an error page, upload one from the browser.
fn config(issuer: &str, login: &str, alias: &str, clients: &[Value]) -> Value {
    let authorize = format!("{issuer}/v1/oauth2/authorize*");
    let complete = json!({
        "task": "Verify complete",
        "match": "*/test/*/callback*",
        "commands": [["wait", "id", "submission_complete", 10]],
    });
    let sign_in = |screenshot: bool| {
        let mut commands = Vec::new();
        if screenshot {
            commands.push(json!([
                "wait",
                "id",
                "sign-in",
                10,
                "Sign in",
                "update-image-placeholder-optional"
            ]));
        }
        commands.push(json!(["click", "id", "sign-in"]));
        json!([{
            "match": authorize,
            "tasks": [
                {"task": "Sign in", "optional": true, "match": format!("{login}/sign-in*"), "commands": commands},
                complete,
            ],
        }])
    };
    let error_page = json!({"browser": [{
        "match": authorize,
        "tasks": [{
            "task": "Expect an error page",
            "match": authorize,
            "commands": [["wait", "xpath", "//*", 10, "Sign-in failed", "update-image-placeholder"]],
        }],
    }]});
    let mut overrides = serde_json::Map::new();
    for module in ["oidcc-prompt-login", "oidcc-max-age-1"] {
        overrides.insert(module.into(), json!({"browser": sign_in(true)}));
    }
    for module in [
        "oidcc-ensure-registered-redirect-uri",
        "oidcc-ensure-redirect-uri-in-authorization-request",
        "oidcc-ensure-request-object-with-redirect-uri",
        "oidcc-redirect-uri-query-added",
        "oidcc-redirect-uri-query-mismatch",
    ] {
        overrides.insert(module.into(), error_page.clone());
    }
    json!({
        "alias": alias,
        "description": "Konklav",
        "server": {"discoveryUrl": format!("{issuer}/.well-known/openid-configuration")},
        "client": clients[0],
        "client2": clients[1],
        // Konklav takes either secret method from any confidential client.
        "client_secret_post": clients[0],
        "browser": sign_in(false),
        "override": overrides,
    })
}

#[derive(serde::Deserialize)]
struct Request {
    login_request: String,
}

fn remembered(page: &LoginPage, headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    let value = cookies
        .split(';')
        .find_map(|c| c.trim().strip_prefix(&format!("{COOKIE}=")))?;
    page.remembered.lock().ok()?.get(value).cloned()
}

/// Answers the login request with `verb` (`accept` or `reject`), returning
/// where to send the browser, or `None` when Konklav refuses.
async fn answer(
    page: &LoginPage,
    request: &str,
    verb: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Option<String> {
    let mut call = page
        .http
        .post(format!(
            "{}/v1/oauth2/login-requests/{request}/{verb}",
            page.konklav
        ))
        .header(header::ORIGIN, &page.origin)
        .header("x-konklav-client", "web");
    if let Some(token) = token {
        call = call.bearer_auth(token);
    }
    if let Some(body) = body {
        call = call.json(&body);
    }
    let reply = call.send().await.ok()?;
    if !reply.status().is_success() {
        return None;
    }
    let body: Value = reply.json().await.ok()?;
    body["redirect_to"].as_str().map(str::to_owned)
}

/// `GET /sign-in?login_request=`: answers at once when it can, or shows the
/// sign-in form.
async fn show(
    State(page): State<Arc<LoginPage>>,
    Query(query): Query<Request>,
    headers: HeaderMap,
) -> Response {
    let view: Value = match page
        .http
        .get(format!(
            "{}/v1/oauth2/login-requests/{}",
            page.konklav, query.login_request
        ))
        .send()
        .await
    {
        Ok(reply) => reply.json().await.unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    let prompt = view["prompt"].as_str().unwrap_or_default();
    let prompts = |value| prompt.split_whitespace().any(|p| p == value);
    let token = remembered(&page, &headers);
    if !prompts("login")
        && let Some(token) = &token
        && let Some(to) = answer(&page, &query.login_request, "accept", Some(token), None).await
    {
        return Redirect::to(&to).into_response();
    }
    if prompts("none") {
        let error = if token.is_some() {
            "interaction_required"
        } else {
            "login_required"
        };
        return match answer(
            &page,
            &query.login_request,
            "reject",
            None,
            Some(json!({"error": error})),
        )
        .await
        {
            Some(to) => Redirect::to(&to).into_response(),
            None => (StatusCode::BAD_GATEWAY, "Konklav refused the refusal").into_response(),
        };
    }
    Html(format!(
        "<!doctype html><title>Sign in</title>\
         <form method=post action=/sign-in>\
         <input type=hidden name=login_request value=\"{}\">\
         <p>Signing in as {EMAIL}</p>\
         <button id=sign-in type=submit>Sign in</button></form>",
        query.login_request
    ))
    .into_response()
}

/// `POST /sign-in`: signs the test user in, remembers it, and accepts.
async fn sign_in(State(page): State<Arc<LoginPage>>, Form(form): Form<Request>) -> Response {
    let login: Value = match page
        .http
        .post(format!("{}/v1/login/password", page.konklav))
        .json(&json!({"identifier": EMAIL, "password": page.password}))
        .send()
        .await
    {
        Ok(reply) => reply.json().await.unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    let Some(token) = login["access_token"].as_str() else {
        return (
            StatusCode::BAD_GATEWAY,
            format!("signing in failed: {login}"),
        )
            .into_response();
    };
    let Some(to) = answer(&page, &form.login_request, "accept", Some(token), None).await else {
        return (StatusCode::BAD_GATEWAY, "Konklav refused the sign-in").into_response();
    };
    let cookie = uuid::Uuid::now_v7().simple().to_string();
    if let Ok(mut remembered) = page.remembered.lock() {
        remembered.insert(cookie.clone(), token.to_owned());
    }
    (
        [(
            header::SET_COOKIE,
            format!("{COOKIE}={cookie}; Path=/; HttpOnly"),
        )],
        Redirect::to(&to),
    )
        .into_response()
}
