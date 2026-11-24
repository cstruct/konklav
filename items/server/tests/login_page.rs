//! The login page built into the server: how it is served, and that a
//! login request handed off to it completes with the calls it makes.

#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashMap;

use axum::http::{Method, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{ISSUER, TestApp};
use konklav_server::login_page::{self, LoginPage, ProviderLink};
use konklav_server::oidc::OpenIdProvider;
use serde_json::json;
use sha2::{Digest, Sha256};

const ID_TOKEN_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUoptOOQL2DZqHV4Q
GpDMUYd6rsbhOjYqdxTU6xh4DmahRANCAARjr/UQTOoK84SKa5ZB1Rg9mLRWjzyy
p1XNGpwF1zXMHj8NrRZRBsdiy2jZvNVSLlPqzmK3P4YLDAtSoKNCeXst
-----END PRIVATE KEY-----";
const REDIRECT: &str = "http://localhost:8000/callback";
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "a-code-verifier-that-is-long-enough-to-be-valid-0123456789";

fn page() -> LoginPage {
    LoginPage {
        title: "Example Corp".into(),
        passkeys: false,
        identity_providers: vec![ProviderLink {
            id: "ops".into(),
            name: "Ops directory".into(),
        }],
        return_to: LoginPage::url(ISSUER),
    }
}

/// An app serving the login page as `serve` sets it up: the page is the
/// login URL, and its origin, the issuer's, may use browser sign-in.
async fn app() -> TestApp {
    TestApp::with_auth(|auth| {
        auth.login_page = Some(page());
        auth.oidc = Some(
            OpenIdProvider::from_pem(
                ID_TOKEN_KEY,
                LoginPage::url(ISSUER),
                format!("{ISSUER}/.well-known/jwks.json"),
            )
            .unwrap(),
        );
        if let Some(browser) = auth.browser.as_mut() {
            browser.allowed_origins.push(ISSUER.into());
        }
    })
    .await
}

fn header<'a>(reply: &'a common::Reply, name: &str) -> &'a str {
    reply
        .headers
        .get(name)
        .unwrap_or_else(|| panic!("no {name} header"))
        .to_str()
        .unwrap()
}

fn assert_protected(reply: &common::Reply) {
    let policy = header(reply, "content-security-policy");
    for directive in [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
    ] {
        assert!(policy.contains(directive), "{policy} lacks {directive}");
    }
    assert!(!policy.contains("unsafe-inline"), "{policy}");
    assert_eq!(header(reply, "x-frame-options"), "DENY");
    assert_eq!(header(reply, "referrer-policy"), "no-referrer");
    assert_eq!(header(reply, "x-content-type-options"), "nosniff");
}

// r[verify oidc.provider.login-page]
// r[verify oidc.provider.login-page.headers]
#[tokio::test(flavor = "multi_thread")]
async fn the_page_is_served_with_headers_that_protect_it() {
    let app = app().await;
    let index = app.send(Method::GET, "/login/", &[], None).await;
    assert_eq!(index.status, StatusCode::OK);
    assert_eq!(header(&index, "content-type"), "text/html; charset=utf-8");
    assert_eq!(header(&index, "cache-control"), "no-store");
    assert_protected(&index);
    let html = index.body.as_str().unwrap();
    assert!(html.contains("<html"), "{html}");

    // Vite's hashed assets, when the page is built rather than a
    // placeholder, are cached for good.
    if login_page::built() {
        let script = html
            .split('"')
            .find(|part| {
                part.starts_with("./assets/") && part.to_ascii_lowercase().ends_with(".js")
            })
            .expect("the page loads a script");
        let asset = app
            .send(
                Method::GET,
                &format!("/login/{}", script.trim_start_matches("./")),
                &[],
                None,
            )
            .await;
        assert_eq!(asset.status, StatusCode::OK);
        assert_eq!(
            header(&asset, "content-type"),
            "text/javascript; charset=utf-8"
        );
        assert!(header(&asset, "cache-control").contains("immutable"));
        assert_protected(&asset);
    }

    let missing = app.send(Method::GET, "/login/nothing.js", &[], None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_protected(&missing);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_keeps_the_login_request_when_its_slash_is_missing() {
    let app = app().await;
    let reply = app
        .send(Method::GET, "/login?login_request=abc", &[], None)
        .await;
    assert_eq!(reply.status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        header(&reply, header::LOCATION.as_str()),
        "/login/?login_request=abc"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_learns_what_it_offers_from_its_config() {
    let app = app().await;
    let reply = app.send(Method::GET, "/login/config.json", &[], None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(header(&reply, "cache-control"), "no-store");
    assert_eq!(
        reply.body,
        json!({
            "title": "Example Corp",
            "passkeys": false,
            "identity_providers": [{"id": "ops", "name": "Ops directory"}],
            "return_to": "https://auth.example/login/",
            "access_requests": false,
        })
    );
}

// r[verify oidc.provider.login-page.access-requests]
#[tokio::test(flavor = "multi_thread")]
async fn the_page_offers_access_requests_when_the_server_takes_them() {
    let app = TestApp::with_auth(|auth| {
        auth.login_page = Some(page());
        auth.access_requests = Some(konklav_server::access_requests::Settings {
            tenants: None,
            retry_after_denial: chrono::Duration::hours(1),
        });
    })
    .await;
    let reply = app.send(Method::GET, "/login/config.json", &[], None).await;
    assert_eq!(reply.body["access_requests"], true);
}

// r[verify oidc.provider.login-page]
#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_served_without_the_page() {
    let app = TestApp::new().await;
    for path in ["/login/", "/login/config.json", "/login"] {
        let reply = app.send(Method::GET, path, &[], None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
}

fn query(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Does what the page does for an OIDC client: reads the login request,
/// signs in as a browser client from the issuer's origin, and accepts.
// r[verify oidc.provider.login-page]
#[tokio::test(flavor = "multi_thread")]
async fn a_login_request_completes_through_the_page() {
    let app = app().await;
    app.human("ada@example.com", PASSWORD).await;
    let registered = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/kubernetes",
            Some(json!({
                "kind": "public",
                "redirect_uris": [REDIRECT],
                "scopes": ["openid", "email", "groups"],
                "audience": "kubernetes",
            })),
        )
        .await;
    assert!(registered.status.is_success(), "{:?}", registered.body);

    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let authorize = reqwest::Url::parse_with_params(
        "http://x/v1/oauth2/authorize",
        [
            ("response_type", "code"),
            ("client_id", "kubernetes"),
            ("redirect_uri", REDIRECT),
            ("scope", "openid email"),
            ("state", "client-state"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ],
    )
    .unwrap();
    let started = app
        .send(
            Method::GET,
            authorize.as_str().trim_start_matches("http://x"),
            &[],
            None,
        )
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
    let login = header(&started, header::LOCATION.as_str()).to_owned();
    assert!(
        login.starts_with("https://auth.example/login/?login_request="),
        "handed off to the page: {login}"
    );
    let request = query(&login)["login_request"].clone();
    let browser = started
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-konklav_authorize="))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .unwrap();

    let page = [("origin", ISSUER), ("x-konklav-client", "konklav-login")];
    let viewed = app
        .send(
            Method::GET,
            &format!("/v1/oauth2/login-requests/{request}"),
            &page,
            None,
        )
        .await;
    assert_eq!(viewed.body["client_id"], "kubernetes");
    let signed_in = app
        .send(
            Method::POST,
            "/v1/login/password",
            &page,
            Some(json!({
                "identifier": "ada@example.com",
                "password": PASSWORD,
                "client": "browser",
            })),
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{:?}", signed_in.body);
    assert!(
        signed_in.body.get("refresh_token").is_none(),
        "a browser login's refresh token is a cookie"
    );
    let token = signed_in.body["access_token"].as_str().unwrap();
    let auth = format!("Bearer {token}");
    let mut headers = page.to_vec();
    headers.push(("authorization", &auth));
    let accepted = app
        .send(
            Method::POST,
            &format!("/v1/oauth2/login-requests/{request}/accept"),
            &headers,
            None,
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);

    let resume = accepted.body["redirect_to"].as_str().unwrap();
    let resumed = app
        .send(
            Method::GET,
            resume.trim_start_matches(ISSUER),
            &[("cookie", &browser)],
            None,
        )
        .await;
    assert_eq!(resumed.status, StatusCode::SEE_OTHER, "{:?}", resumed.body);
    let back = header(&resumed, header::LOCATION.as_str()).to_owned();
    assert!(back.starts_with(REDIRECT), "{back}");
    let params = query(&back);
    assert_eq!(params["state"], "client-state");
    assert!(params.contains_key("code"));
}
