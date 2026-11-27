//! The native login hand-off: an app on the subject's computer signs in
//! through the login application and gets a bound session of its own
//! through a loopback redirect.

mod common;

use std::collections::HashMap;

use axum::http::{Method, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use common::{ISSUER, ORIGIN, TestApp};
use konklav_server::native_handoff::Settings;
use konklav_test_support::DpopKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LOGIN_URL: &str = "https://login.example/";
const REDIRECT: &str = "http://127.0.0.1:53682/callback";
const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "a-code-verifier-that-is-long-enough-to-be-valid-0123456789";
const COOKIE: &str = "__Host-konklav_authorize";

fn settings(lifetime: Duration) -> Settings {
    Settings {
        login_url: LOGIN_URL.into(),
        apps: vec!["konklav-cli".into()],
        session_lifetime: lifetime,
    }
}

async fn app() -> TestApp {
    TestApp::with_auth(|auth| auth.native_handoff = Some(settings(Duration::hours(12)))).await
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

fn query(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn location(reply: &common::Reply) -> String {
    reply.headers[header::LOCATION].to_str().unwrap().to_owned()
}

fn cookie(reply: &common::Reply) -> Option<String> {
    reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{COOKIE}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
}

/// The authorize URI, with `extra` replacing (or, when empty, removing)
/// parameters.
fn authorize_uri(key: &DpopKey, extra: &[(&str, &str)]) -> String {
    let challenge = challenge();
    let jkt = key.jkt();
    let mut params = vec![
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("dpop_jkt", jkt.as_str()),
        ("state", "cli-state"),
        ("app", "konklav-cli"),
    ];
    for (key, value) in extra {
        params.retain(|(k, _)| k != key);
        if !value.is_empty() {
            params.push((key, value));
        }
    }
    reqwest::Url::parse_with_params("http://x/v1/login-requests/native/authorize", &params)
        .unwrap()
        .as_str()
        .trim_start_matches("http://x")
        .to_owned()
}

struct Started {
    request: String,
    browser: String,
}

async fn start(app: &TestApp, key: &DpopKey) -> Started {
    let started = app
        .send(Method::GET, &authorize_uri(key, &[]), &[], None)
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
    let login_url = location(&started);
    assert!(login_url.starts_with(LOGIN_URL), "{login_url}");
    Started {
        request: query(&login_url)["login_request"].clone(),
        browser: cookie(&started).unwrap(),
    }
}

/// The login application answers: `accept` with `token`, or `reject`.
async fn answer(
    app: &TestApp,
    path: &str,
    verb: &str,
    token: &str,
    body: Option<Value>,
) -> common::Reply {
    let auth = format!("Bearer {token}");
    app.send(
        Method::POST,
        &format!("{path}/{verb}"),
        &[
            ("authorization", &auth),
            ("origin", ORIGIN),
            ("x-konklav-client", "web"),
        ],
        body,
    )
    .await
}

/// Follows `redirect_to` in the browser with `cookie`.
async fn resume(app: &TestApp, answered: &common::Reply, cookie: &str) -> common::Reply {
    let resume = answered.body["redirect_to"].as_str().unwrap();
    assert!(
        resume.starts_with(&format!("{ISSUER}/v1/login-requests/native/resume?")),
        "{resume}"
    );
    app.send(
        Method::GET,
        resume.trim_start_matches(ISSUER),
        &[("cookie", cookie)],
        None,
    )
    .await
}

async fn browser_login(app: &TestApp) -> String {
    let login = app.login(EMAIL, PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    login.body["access_token"].as_str().unwrap().to_owned()
}

/// Runs authorize, accept and resume, returning the code.
async fn code_for(app: &TestApp, key: &DpopKey, login_token: &str) -> String {
    let started = start(app, key).await;
    let accepted = answer(
        app,
        &format!("/v1/login-requests/{}", started.request),
        "accept",
        login_token,
        None,
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    let resumed = resume(app, &accepted, &started.browser).await;
    assert_eq!(resumed.status, StatusCode::SEE_OTHER, "{:?}", resumed.body);
    let back = location(&resumed);
    assert!(back.starts_with(&format!("{REDIRECT}?")), "{back}");
    let params = query(&back);
    assert_eq!(params["state"], "cli-state");
    assert_eq!(params["iss"], ISSUER);
    params["code"].clone()
}

const TOKEN_URL: &str = "/v1/login-requests/native/token";

async fn exchange(app: &TestApp, key: Option<&DpopKey>, code: &str) -> common::Reply {
    exchange_with(app, key, code, VERIFIER, REDIRECT).await
}

async fn exchange_with(
    app: &TestApp,
    key: Option<&DpopKey>,
    code: &str,
    verifier: &str,
    redirect: &str,
) -> common::Reply {
    let proof = key.map(|key| key.proof("POST", &format!("{ISSUER}{TOKEN_URL}"), None));
    let headers: Vec<(&str, &str)> = proof.iter().map(|p| ("dpop", p.as_str())).collect();
    app.send(
        Method::POST,
        TOKEN_URL,
        &headers,
        Some(json!({"code": code, "code_verifier": verifier, "redirect_uri": redirect})),
    )
    .await
}

/// Calls the API with a bound access token.
async fn call(
    app: &TestApp,
    key: &DpopKey,
    method: Method,
    path: &str,
    token: &str,
) -> common::Reply {
    let proof = key.proof(method.as_str(), &format!("{ISSUER}{path}"), Some(token));
    let auth = format!("DPoP {token}");
    app.send(
        method,
        path,
        &[("authorization", &auth), ("dpop", &proof)],
        None,
    )
    .await
}

async fn refresh(app: &TestApp, key: &DpopKey, refresh_token: &str) -> common::Reply {
    let proof = key.proof("POST", &format!("{ISSUER}/v1/refresh"), None);
    app.send(
        Method::POST,
        "/v1/refresh",
        &[("dpop", &proof)],
        Some(json!({"refresh_token": refresh_token})),
    )
    .await
}

async fn operator(app: &TestApp) -> String {
    let subject = app.human(EMAIL, PASSWORD).await;
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": "konklav.admin"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    subject
}

async fn session_expiry(app: &TestApp, session: &str) -> chrono::DateTime<Utc> {
    let mut conn = app.db.pool().get().await.unwrap();
    konklav_store::sessions::get(&mut conn, session.parse().unwrap())
        .await
        .unwrap()
        .expires_at
}

// r[verify session.native-handoff.session]
// r[verify session.native-handoff.code]
// r[verify session.native-handoff.disabled]
// r[verify session.login-requests.paths]
#[tokio::test(flavor = "multi_thread")]
async fn an_app_signs_in_through_the_browser_and_gets_a_bound_session() {
    // No OpenID provider is configured.
    let app = app().await;
    let subject = operator(&app).await;
    let key = DpopKey::new(7);
    let login_token = browser_login(&app).await;

    let started = start(&app, &key).await;
    for prefix in ["/v1/login-requests", "/v1/oauth2/login-requests"] {
        let viewed = app
            .send(
                Method::GET,
                &format!("{prefix}/{}", started.request),
                &[],
                None,
            )
            .await;
        assert_eq!(viewed.status, StatusCode::OK, "{:?}", viewed.body);
        assert_eq!(viewed.body, json!({"kind": "native", "app": "konklav-cli"}));
    }
    let accepted = answer(
        &app,
        &format!("/v1/login-requests/{}", started.request),
        "accept",
        &login_token,
        None,
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    let resumed = resume(&app, &accepted, &started.browser).await;
    let code = query(&location(&resumed))["code"].clone();

    let exchanged = exchange(&app, Some(&key), &code).await;
    assert_eq!(exchanged.status, StatusCode::OK, "{:?}", exchanged.body);
    assert_eq!(exchanged.headers[header::CACHE_CONTROL], "no-store");
    let access = exchanged.body["access_token"].as_str().unwrap().to_owned();
    let refresh_token = exchanged.body["refresh_token"].as_str().unwrap().to_owned();
    let claims = konklav_token::decode_claims_unverified(&access).unwrap();
    assert_eq!(claims.cnf.unwrap().jkt, key.jkt());
    assert_eq!(claims.sub.to_string(), subject);
    assert_eq!(claims.aud, common::AUDIENCE);

    // It reaches the control plane, as the operator.
    let listed = call(&app, &key, Method::GET, "/v1/subjects", &access).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    // Only with its key.
    let stolen = app.with_bearer(Method::GET, "/v1/subjects", &access).await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);

    // Signing out in the browser leaves it.
    let signed_out = app
        .with_bearer(Method::POST, "/v1/sign-out", &login_token)
        .await;
    assert!(signed_out.status.is_success(), "{:?}", signed_out.body);
    let refreshed = refresh(&app, &key, &refresh_token).await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    assert!(
        konklav_token::decode_claims_unverified(refreshed.body["access_token"].as_str().unwrap())
            .unwrap()
            .cnf
            .is_some()
    );
}

// r[verify session.native-handoff.lifetime]
#[tokio::test(flavor = "multi_thread")]
async fn native_sessions_get_the_hand_offs_lifetime_capped_by_the_sign_in() {
    let app = app().await;
    operator(&app).await;
    let key = DpopKey::new(7);
    let login_token = browser_login(&app).await;
    let code = code_for(&app, &key, &login_token).await;
    let exchanged = exchange(&app, Some(&key), &code).await;
    let session = exchanged.body["session_id"].as_str().unwrap().to_owned();
    let expires = session_expiry(&app, &session).await;
    let expected = Utc::now() + Duration::hours(12);
    assert!((expires - expected).num_seconds().abs() < 60, "{expires}");
    // Refreshing doesn't extend it.
    let refreshed = refresh(
        &app,
        &key,
        exchanged.body["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    assert_eq!(session_expiry(&app, &session).await, expires);

    // A sign-in that ends sooner ends it sooner.
    let app = TestApp::with_auth(|auth| {
        auth.session_lifetime = Duration::hours(1);
        auth.native_handoff = Some(settings(Duration::hours(12)));
    })
    .await;
    operator(&app).await;
    let login_token = browser_login(&app).await;
    let code = code_for(&app, &key, &login_token).await;
    let exchanged = exchange(&app, Some(&key), &code).await;
    let session = exchanged.body["session_id"].as_str().unwrap();
    let expires = session_expiry(&app, session).await;
    assert!(expires <= Utc::now() + Duration::hours(1), "{expires}");
}

// r[verify session.native-handoff.code]
#[tokio::test(flavor = "multi_thread")]
async fn a_reused_code_fails_and_revokes_the_session() {
    let app = app().await;
    operator(&app).await;
    let key = DpopKey::new(7);
    let login_token = browser_login(&app).await;
    let code = code_for(&app, &key, &login_token).await;
    let first = exchange(&app, Some(&key), &code).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let again = exchange(&app, Some(&key), &code).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED, "{:?}", again.body);
    assert_eq!(again.code(), "INVALID_CREDENTIALS");
    let refreshed = refresh(&app, &key, first.body["refresh_token"].as_str().unwrap()).await;
    assert_eq!(refreshed.status, StatusCode::UNAUTHORIZED);
}

// r[verify session.native-handoff.dpop]
// r[verify session.native-handoff.pkce]
#[tokio::test(flavor = "multi_thread")]
async fn the_code_needs_the_verifier_the_redirect_and_the_key() {
    let app = app().await;
    operator(&app).await;
    let key = DpopKey::new(7);
    let login_token = browser_login(&app).await;

    let code = code_for(&app, &key, &login_token).await;
    let unproven = exchange(&app, None, &code).await;
    assert_eq!(unproven.status, StatusCode::UNAUTHORIZED);
    assert!(unproven.headers.contains_key(header::WWW_AUTHENTICATE));
    let other_key = exchange(&app, Some(&DpopKey::new(8)), &code).await;
    assert_eq!(
        other_key.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        other_key.body
    );
    let wrong_verifier = exchange_with(
        &app,
        Some(&key),
        &code,
        "another-verifier-that-is-long-enough-to-be-valid-0123456789",
        REDIRECT,
    )
    .await;
    assert_eq!(wrong_verifier.status, StatusCode::UNAUTHORIZED);
    let wrong_redirect = exchange_with(
        &app,
        Some(&key),
        &code,
        VERIFIER,
        "http://127.0.0.1:1/callback",
    )
    .await;
    assert_eq!(wrong_redirect.status, StatusCode::UNAUTHORIZED);
    // None of those used the code up.
    let exchanged = exchange(&app, Some(&key), &code).await;
    assert_eq!(exchanged.status, StatusCode::OK, "{:?}", exchanged.body);
}

// r[verify session.native-handoff.redirect]
// r[verify session.native-handoff.pkce]
// r[verify session.native-handoff.dpop]
#[tokio::test(flavor = "multi_thread")]
async fn bad_requests_get_a_page_and_no_redirect() {
    let app = app().await;
    let key = DpopKey::new(7);
    for extra in [
        [("redirect_uri", "http://localhost:53682/callback")],
        [("redirect_uri", "http://192.0.2.1:53682/callback")],
        [("redirect_uri", "http://127.0.0.1:53682/elsewhere")],
        [("redirect_uri", "com.example.app:/callback")],
        [("redirect_uri", "")],
        [("dpop_jkt", "")],
        [("dpop_jkt", "not-a-thumbprint")],
        [("code_challenge", "")],
        [("code_challenge_method", "plain")],
        [("app", "something-else")],
        [("state", "")],
    ] {
        let reply = app
            .send(Method::GET, &authorize_uri(&key, &extra), &[], None)
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{extra:?}");
        assert!(!reply.headers.contains_key(header::LOCATION), "{extra:?}");
        assert!(
            reply
                .body
                .as_str()
                .is_some_and(|page| page.contains("<h1>")),
            "{extra:?}: {:?}",
            reply.body
        );
    }
}

// r[verify session.native-handoff.disabled]
#[tokio::test(flavor = "multi_thread")]
async fn the_hand_off_is_off_unless_configured() {
    let app = TestApp::new().await;
    let key = DpopKey::new(7);
    let reply = app
        .send(Method::GET, &authorize_uri(&key, &[]), &[], None)
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(!reply.headers.contains_key(header::LOCATION));
}

// r[verify session.native-handoff.code]
#[tokio::test(flavor = "multi_thread")]
async fn another_browser_cannot_complete_the_request() {
    let app = app().await;
    operator(&app).await;
    let key = DpopKey::new(7);
    let login_token = browser_login(&app).await;
    // An attacker starts a request and sends the login link to a victim,
    // who accepts it.
    let attacker = start(&app, &key).await;
    let accepted = answer(
        &app,
        &format!("/v1/login-requests/{}", attacker.request),
        "accept",
        &login_token,
        None,
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK);
    // The victim's browser has no cookie for it.
    let resumed = resume(&app, &accepted, "").await;
    assert_eq!(resumed.status, StatusCode::BAD_REQUEST);
    assert!(!resumed.headers.contains_key(header::LOCATION));
    // The attacker's has no acceptance.
    let guessed = app
        .send(
            Method::GET,
            &format!(
                "/v1/login-requests/native/resume?login_request={}&acceptance=guess",
                attacker.request
            ),
            &[("cookie", &attacker.browser)],
            None,
        )
        .await;
    assert_eq!(guessed.status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_request_sends_the_error_to_the_app() {
    let app = app().await;
    operator(&app).await;
    let key = DpopKey::new(7);
    let login_token = browser_login(&app).await;
    let started = start(&app, &key).await;
    let refused = answer(
        &app,
        &format!("/v1/oauth2/login-requests/{}", started.request),
        "reject",
        &login_token,
        Some(json!({"error": "access_denied"})),
    )
    .await;
    assert_eq!(refused.status, StatusCode::OK, "{:?}", refused.body);
    let resumed = resume(&app, &refused, &started.browser).await;
    assert_eq!(resumed.status, StatusCode::SEE_OTHER, "{:?}", resumed.body);
    let params = query(&location(&resumed));
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["state"], "cli-state");
    assert!(!params.contains_key("code"));
    // Answered once.
    let again = answer(
        &app,
        &format!("/v1/login-requests/{}", started.request),
        "accept",
        &login_token,
        None,
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "{:?}", again.body);
}
