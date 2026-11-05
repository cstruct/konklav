#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashMap;

use axum::http::{Method, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{ISSUER, ORIGIN, TestApp};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{DecodingKey, Validation};
use konklav_server::oidc::OpenIdProvider;
use konklav_test_support::DpopKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ID_TOKEN_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUoptOOQL2DZqHV4Q
GpDMUYd6rsbhOjYqdxTU6xh4DmahRANCAARjr/UQTOoK84SKa5ZB1Rg9mLRWjzyy
p1XNGpwF1zXMHj8NrRZRBsdiy2jZvNVSLlPqzmK3P4YLDAtSoKNCeXst
-----END PRIVATE KEY-----";
const LOGIN_URL: &str = "https://login.example/";
const REDIRECT: &str = "https://console.example/callback";
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "a-code-verifier-that-is-long-enough-to-be-valid-0123456789";

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

fn cookie(reply: &common::Reply, name: &str) -> Option<String> {
    reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
}

struct World {
    app: TestApp,
    secret: String,
    subject: String,
    /// The login application's access token.
    login_token: String,
}

fn provider() -> OpenIdProvider {
    OpenIdProvider::from_pem(
        ID_TOKEN_KEY,
        LOGIN_URL.into(),
        format!("{ISSUER}/.well-known/jwks.json"),
    )
    .unwrap()
}

async fn world() -> World {
    world_with(provider()).await
}

async fn world_with(provider: OpenIdProvider) -> World {
    world_in(TestApp::with_openid_provider(provider).await).await
}

async fn world_in(app: TestApp) -> World {
    let subject = app.human("ada@example.com", PASSWORD).await;
    for (method, path, body) in [
        (
            Method::PUT,
            "/v1/catalog".to_owned(),
            json!({"actions": [{"name": "ops:run"}]}),
        ),
        (
            Method::PUT,
            "/v1/tenants/root/roles/ops-admin".to_owned(),
            json!({"policies": [{"action": "ops:run", "effect": "allow"}]}),
        ),
        (
            Method::PUT,
            "/v1/tenants/root/roles/hidden".to_owned(),
            json!({}),
        ),
        (
            Method::POST,
            format!("/v1/subjects/{subject}/global-assignments"),
            json!({"role": "ops-admin"}),
        ),
        (
            Method::POST,
            format!("/v1/subjects/{subject}/global-assignments"),
            json!({"role": "hidden"}),
        ),
        (
            Method::PUT,
            "/v1/oidc/clients/console".to_owned(),
            json!({
                "kind": "confidential",
                "redirect_uris": [REDIRECT],
                "scopes": ["openid", "email", "phone", "groups", "tenant", "profile"],
                "audience": "console",
                "visible_groups": ["ops-*"],
            }),
        ),
    ] {
        let reply = app.control(method, &path, Some(body)).await;
        assert!(reply.status.is_success(), "{path}: {:?}", reply.body);
    }
    let secret = app
        .control(Method::POST, "/v1/oidc/clients/console/secret", None)
        .await
        .body["client_secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let login = app.login("ada@example.com", PASSWORD).await;
    World {
        app,
        secret,
        subject,
        login_token: login.body["access_token"].as_str().unwrap().to_owned(),
    }
}

fn authorize_uri(extra: &[(&str, &str)]) -> String {
    let challenge = challenge();
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", "console"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid email groups"),
        ("state", "client-state"),
        ("nonce", "client-nonce"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    for (key, value) in extra {
        params.retain(|(k, _)| k != key);
        if !value.is_empty() {
            params.push((key, value));
        }
    }
    reqwest::Url::parse_with_params("http://x/v1/oauth2/authorize", &params)
        .unwrap()
        .as_str()
        .trim_start_matches("http://x")
        .to_owned()
}

/// Runs authorize → accept → resume, returning the code.
async fn authorize(world: &World, extra: &[(&str, &str)]) -> String {
    let app = &world.app;
    let started = app
        .send(Method::GET, &authorize_uri(extra), &[], None)
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
    let login_url = location(&started);
    assert!(login_url.starts_with(LOGIN_URL));
    let request = query(&login_url)["login_request"].clone();
    let browser = cookie(&started, "__Host-konklav_authorize").unwrap();

    let viewed = app
        .send(
            Method::GET,
            &format!("/v1/oauth2/login-requests/{request}"),
            &[],
            None,
        )
        .await;
    let client = extra
        .iter()
        .find(|(k, _)| *k == "client_id")
        .map_or("console", |(_, v)| *v);
    assert_eq!(viewed.body["client_id"], client);

    let auth = format!("Bearer {}", world.login_token);
    let accepted = app
        .send(
            Method::POST,
            &format!("/v1/oauth2/login-requests/{request}/accept"),
            &[
                ("authorization", &auth),
                ("origin", ORIGIN),
                ("x-konklav-client", "web"),
            ],
            None,
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    let resume = accepted.body["redirect_to"].as_str().unwrap();
    let path = resume.trim_start_matches(ISSUER);
    let resumed = app
        .send(Method::GET, path, &[("cookie", &browser)], None)
        .await;
    assert_eq!(resumed.status, StatusCode::SEE_OTHER, "{:?}", resumed.body);
    let back = location(&resumed);
    assert!(back.starts_with(REDIRECT));
    let params = query(&back);
    assert_eq!(params["state"], "client-state");
    assert_eq!(params["iss"], ISSUER);
    params["code"].clone()
}

fn basic(secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("console:{secret}")))
}

async fn exchange(world: &World, code: &str, verifier: &str) -> common::Reply {
    world
        .app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic(&world.secret))],
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", verifier),
            ],
        )
        .await
}

async fn id_token_claims(app: &TestApp, token: &str) -> Value {
    let jwks: Value = app
        .send(Method::GET, "/.well-known/jwks.json", &[], None)
        .await
        .body;
    let ec = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kty"] == "EC")
        .expect("the ID-token key is published");
    let jwk: Jwk = serde_json::from_value(ec.clone()).unwrap();
    let header = jsonwebtoken::decode_header(token).unwrap();
    assert_eq!(header.kid.as_deref(), ec["kid"].as_str());
    let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_audience(&["console"]);
    validation.set_issuer(&[ISSUER]);
    jsonwebtoken::decode::<Value>(token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation)
        .unwrap()
        .claims
}

// r[verify oidc.provider.code-flow]
// r[verify oidc.provider.login-handoff]
#[tokio::test(flavor = "multi_thread")]
async fn a_request_started_in_one_browser_cannot_be_accepted_in_another() {
    let world = world().await;
    let app = &world.app;
    // The attacker starts a request and sends its login link to a victim.
    let started = app.send(Method::GET, &authorize_uri(&[]), &[], None).await;
    let request = query(&location(&started))["login_request"].clone();
    let attacker = cookie(&started, "__Host-konklav_authorize").unwrap();
    // The victim, signed in, accepts it.
    let auth = format!("Bearer {}", world.login_token);
    let accepted = app
        .send(
            Method::POST,
            &format!("/v1/oauth2/login-requests/{request}/accept"),
            &[
                ("authorization", &auth),
                ("origin", ORIGIN),
                ("x-konklav-client", "web"),
            ],
            None,
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    let victim_resume = accepted.body["redirect_to"].as_str().unwrap();
    let victim_resume = victim_resume.trim_start_matches(ISSUER).to_owned();

    // The attacker's browser, without the acceptance, gets no code.
    let attacker_resume = format!("/v1/oauth2/authorize/resume?login_request={request}");
    let guessed = format!("{attacker_resume}&acceptance=guess");
    for path in [&attacker_resume, &guessed] {
        let resumed = app
            .send(Method::GET, path, &[("cookie", &attacker)], None)
            .await;
        assert_eq!(resumed.status, StatusCode::BAD_REQUEST, "{path}");
    }
    // The victim's browser, without the cookie, gets none either.
    let resumed = app.send(Method::GET, &victim_resume, &[], None).await;
    assert_eq!(resumed.status, StatusCode::BAD_REQUEST);
}

// r[verify oidc.provider.login-handoff]
// r[verify oidc.provider.id-token]
// r[verify oidc.provider.algorithms]
// r[verify oidc.provider.tokens]
// r[verify oidc.provider.claims]
// r[verify oidc.provider.groups]
#[tokio::test(flavor = "multi_thread")]
async fn clients_sign_subjects_in_with_the_code_flow() {
    let world = world().await;
    let app = &world.app;
    let code = authorize(&world, &[]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    assert_eq!(tokens.headers[header::CACHE_CONTROL], "no-store");

    let id = id_token_claims(app, tokens.body["id_token"].as_str().unwrap()).await;
    assert_eq!(id["sub"], world.subject.as_str());
    assert_eq!(id["nonce"], "client-nonce");
    assert_eq!(id["azp"], "console");
    assert_eq!(id["amr"], json!(["pwd"]));
    assert_eq!(id["acr"], "urn:konklav:acr:1");
    // Scope claims are served from userinfo only.
    assert!(id.get("email").is_none(), "{id:?}");
    assert!(id.get("email_verified").is_none(), "{id:?}");
    assert_eq!(
        id["groups"],
        json!(["ops-admin"]),
        "only visible global roles"
    );

    let access = tokens.body["access_token"].as_str().unwrap();
    let claims = konklav_token::decode_claims_unverified(access).unwrap();
    assert_eq!(claims.aud, "console", "the client's audience");
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert_eq!(info.body["sub"], world.subject.as_str());
    assert_eq!(info.body["groups"], json!(["ops-admin"]));

    // Refresh rotates; the old refresh token then ends the session.
    let refresh = tokens.body["refresh_token"].as_str().unwrap();
    let refreshed = app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic(&world.secret))],
            &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    assert!(refreshed.body["id_token"].is_string());
    assert_ne!(
        refreshed.body["refresh_token"],
        tokens.body["refresh_token"]
    );
    let reused = app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic(&world.secret))],
            &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
        )
        .await;
    assert_eq!(reused.body["error"], "invalid_grant");

    // A client's refresh tokens don't work at /v1/refresh, and vice versa.
    let plain = app
        .post(
            "/v1/refresh",
            json!({"refresh_token": refreshed.body["refresh_token"]}),
        )
        .await;
    assert_eq!(plain.code(), "SESSION_ENDED");
}

// r[verify oidc.provider.cors]
#[tokio::test(flavor = "multi_thread")]
async fn browser_apps_of_public_clients_may_call_the_token_endpoints() {
    let world = world().await;
    let app = &world.app;
    for (id, kind) in [("spa", "public"), ("server", "confidential")] {
        let registered = app
            .control(
                Method::PUT,
                &format!("/v1/oidc/clients/{id}"),
                Some(json!({
                    "kind": kind,
                    "redirect_uris": [format!("https://{id}.example/callback")],
                    "audience": id,
                })),
            )
            .await;
        assert_eq!(registered.status, StatusCode::OK, "{:?}", registered.body);
    }
    let allowed = |reply: &common::Reply| {
        reply
            .headers
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap().to_owned())
    };
    let preflight = |path: &'static str, origin: &'static str| {
        let app = &app;
        async move {
            app.send(
                Method::OPTIONS,
                path,
                &[
                    ("origin", origin),
                    ("access-control-request-method", "POST"),
                    ("access-control-request-headers", "authorization"),
                ],
                None,
            )
            .await
        }
    };

    for path in [
        "/v1/oauth2/token",
        "/v1/oauth2/revoke",
        "/v1/oauth2/userinfo",
    ] {
        let answered = preflight(path, "https://spa.example").await;
        assert_eq!(answered.status, StatusCode::NO_CONTENT, "{path}");
        assert_eq!(allowed(&answered).as_deref(), Some("https://spa.example"));
        assert!(
            answered
                .headers
                .get("access-control-allow-credentials")
                .is_none()
        );
        let methods = answered.headers["access-control-allow-methods"]
            .to_str()
            .unwrap();
        assert!(methods.contains("POST"), "{methods}");
        for origin in ["https://server.example", "https://elsewhere.example"] {
            assert_eq!(
                allowed(&preflight(path, origin).await),
                None,
                "{path} {origin}"
            );
        }
    }

    // The answer itself is readable from the client's origin, even an error.
    let refused = app
        .send_form(
            "/v1/oauth2/token",
            &[("origin", "https://spa.example")],
            &[
                ("grant_type", "authorization_code"),
                ("client_id", "spa"),
                ("code", "nope"),
            ],
        )
        .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
    assert_eq!(allowed(&refused).as_deref(), Some("https://spa.example"));
    assert!(refused.headers["vary"].to_str().unwrap().contains("origin"));

    // A disabled client's origin is no longer allowed.
    app.control(Method::DELETE, "/v1/oidc/clients/spa", None)
        .await;
    assert_eq!(
        allowed(&preflight("/v1/oauth2/token", "https://spa.example").await),
        None
    );

    // Discovery and the key set are public; the rest of the surface isn't.
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
    ] {
        let read = app
            .send(
                Method::GET,
                path,
                &[("origin", "https://elsewhere.example")],
                None,
            )
            .await;
        assert_eq!(read.status, StatusCode::OK, "{path}");
        assert_eq!(allowed(&read).as_deref(), Some("*"), "{path}");
        let preflight = app
            .send(
                Method::OPTIONS,
                path,
                &[("origin", "https://elsewhere.example")],
                None,
            )
            .await;
        assert_eq!(allowed(&preflight).as_deref(), Some("*"), "{path}");
    }
    let login = app
        .send(
            Method::OPTIONS,
            "/v1/login/password",
            &[("origin", "https://spa.example")],
            None,
        )
        .await;
    assert_eq!(allowed(&login), None);
}

// r[verify oidc.provider.discovery]
// r[verify oidc.provider.dpop.discovery]
#[tokio::test(flavor = "multi_thread")]
async fn discovery_lists_the_endpoints() {
    let world = world().await;
    let document = world
        .app
        .send(Method::GET, "/.well-known/openid-configuration", &[], None)
        .await;
    assert_eq!(document.status, StatusCode::OK);
    assert_eq!(document.body["issuer"], ISSUER);
    assert_eq!(
        document.body["token_endpoint"],
        format!("{ISSUER}/v1/oauth2/token")
    );
    assert_eq!(
        document.body["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(
        document.body["dpop_signing_alg_values_supported"],
        json!(["ES256", "EdDSA"])
    );
    for unsupported in [
        "request_parameter_supported",
        "request_uri_parameter_supported",
    ] {
        assert_eq!(document.body[unsupported], false, "{unsupported}");
    }
    assert_eq!(document.body["claims_parameter_supported"], true);
    let plain = TestApp::new().await;
    let missing = plain
        .send(Method::GET, "/.well-known/openid-configuration", &[], None)
        .await;
    assert_eq!(
        missing.status,
        StatusCode::NOT_FOUND,
        "off unless configured"
    );
}

// r[verify oidc.provider.clients]
// r[verify oidc.provider.error-page]
// r[verify oidc.provider.code-flow]
// r[verify oidc.provider.request-objects]
// r[verify oidc.provider.prompt]
#[tokio::test(flavor = "multi_thread")]
async fn bad_requests_are_refused_without_leaking_codes() {
    let world = world().await;
    let app = &world.app;
    // Unknown clients and unregistered redirect URIs never redirect.
    for extra in [
        [("client_id", "nobody")],
        [("redirect_uri", "https://evil.example/")],
    ] {
        let reply = app
            .send(Method::GET, &authorize_uri(&extra), &[], None)
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{extra:?}");
        assert!(reply.headers.get(header::LOCATION).is_none());
        let page = reply.body.as_str().unwrap_or_default();
        assert!(
            page.contains("Sign-in failed") && page.contains("INVALID_REQUEST"),
            "{page}"
        );
    }
    // Other problems go back to the client.
    for (extra, error) in [
        (vec![("code_challenge", "")], "invalid_request"),
        (vec![("code_challenge_method", "plain")], "invalid_request"),
        (vec![("scope", "email")], "invalid_scope"),
        (vec![("response_type", "")], "invalid_request"),
        (
            vec![("request", "eyJhbGciOiJub25lIn0.e30.")],
            "request_not_supported",
        ),
        (
            vec![("request_uri", "https://rp.example/request.jwt")],
            "request_uri_not_supported",
        ),
        (vec![("prompt", "none login")], "invalid_request"),
        (vec![("claims", "not json")], "invalid_request"),
        (
            vec![("claims", r#"{"userinfo": ["name"]}"#)],
            "invalid_request",
        ),
        (
            vec![("response_type", "token")],
            "unsupported_response_type",
        ),
    ] {
        let reply = app
            .send(Method::GET, &authorize_uri(&extra), &[], None)
            .await;
        let back = query(&location(&reply));
        assert_eq!(back["error"], error, "{extra:?}");
        assert_eq!(back["state"], "client-state");
    }

    let code = authorize(&world, &[]).await;
    let wrong_verifier = exchange(&world, &code, "another-verifier-another-verifier-another").await;
    assert_eq!(wrong_verifier.body["error"], "invalid_grant");
    let wrong_secret = app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic("not the secret"))],
            &[("grant_type", "authorization_code"), ("code", &code)],
        )
        .await;
    assert_eq!(wrong_secret.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_secret.body["error"], "invalid_client");

    // Resuming needs the browser that started the request.
    let started = app.send(Method::GET, &authorize_uri(&[]), &[], None).await;
    let request = query(&location(&started))["login_request"].clone();
    let auth = format!("Bearer {}", world.login_token);
    app.send(
        Method::POST,
        &format!("/v1/oauth2/login-requests/{request}/accept"),
        &[
            ("authorization", &auth),
            ("origin", ORIGIN),
            ("x-konklav-client", "web"),
        ],
        None,
    )
    .await;
    let foreign = app
        .send(
            Method::GET,
            &format!("/v1/oauth2/authorize/resume?login_request={request}"),
            &[],
            None,
        )
        .await;
    assert_eq!(foreign.code(), "INVALID_REQUEST");
}

// r[verify oidc.provider.tenant]
#[tokio::test(flavor = "multi_thread")]
async fn requests_are_only_accepted_by_sessions_that_satisfy_them() {
    let world = world().await;
    let app = &world.app;
    let auth = format!("Bearer {}", world.login_token);
    for (extra, reason) in [
        (vec![("acr_values", "urn:konklav:acr:2")], "acr_values"),
        (
            vec![("scope", &*format!("openid tenant:{}", uuid::Uuid::now_v7()))],
            "tenant",
        ),
    ] {
        let started = app
            .send(Method::GET, &authorize_uri(&extra), &[], None)
            .await;
        let request = query(&location(&started))["login_request"].clone();
        let accepted = app
            .send(
                Method::POST,
                &format!("/v1/oauth2/login-requests/{request}/accept"),
                &[
                    ("authorization", &auth),
                    ("origin", ORIGIN),
                    ("x-konklav-client", "web"),
                ],
                None,
            )
            .await;
        assert_eq!(accepted.code(), "FORBIDDEN", "{reason}");
    }

    // Disabling the client ends its sessions.
    let code = authorize(&world, &[]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    app.control(Method::DELETE, "/v1/oidc/clients/console", None)
        .await;
    let access = tokens.body["access_token"].as_str().unwrap();
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.status, StatusCode::UNAUTHORIZED);
    let started = app.send(Method::GET, &authorize_uri(&[]), &[], None).await;
    assert_eq!(started.status, StatusCode::BAD_REQUEST);
    assert!(
        started
            .body
            .as_str()
            .unwrap_or_default()
            .contains("INVALID_REQUEST")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn public_clients_use_pkce_alone_and_can_get_eddsa_id_tokens() {
    let world = world().await;
    let app = &world.app;
    let registered = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/spa",
            Some(json!({
                "kind": "public",
                "redirect_uris": [REDIRECT],
                "audience": "spa",
                "id_token_alg": "EdDSA",
                "refresh": false,
            })),
        )
        .await;
    assert_eq!(registered.status, StatusCode::OK, "{:?}", registered.body);
    let code = authorize(&world, &[("client_id", "spa"), ("scope", "openid")]).await;
    let tokens = app
        .send_form(
            "/v1/oauth2/token",
            &[],
            &[
                ("grant_type", "authorization_code"),
                ("client_id", "spa"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    assert!(tokens.body.get("refresh_token").is_none(), "refresh is off");
    let id_token = tokens.body["id_token"].as_str().unwrap();
    let header = jsonwebtoken::decode_header(id_token).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    let claims = jsonwebtoken::dangerous::insecure_decode::<Value>(id_token)
        .unwrap()
        .claims;
    assert_eq!(claims["aud"], "spa");

    // A client's access token isn't accepted by Konklav's own API.
    let access = tokens.body["access_token"].as_str().unwrap();
    let auth = format!("Bearer {access}");
    let own = app
        .send(
            Method::POST,
            "/v1/sign-out",
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(own.status, StatusCode::UNAUTHORIZED);
}

const KEY_X: &str = "Y6_1EEzqCvOEimuWQdUYPZi0Vo88sqdVzRqcBdc1zB4";
const KEY_Y: &str = "Pw2tFlEGx2LLaNm81VIuU-rOYrc_hgsMC1Kgo0J5ey0";

fn assertion(client: &str, jti: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("robot-key".into());
    jsonwebtoken::encode(
        &header,
        &json!({
            "iss": client, "sub": client, "aud": format!("{ISSUER}/v1/oauth2/token"),
            "jti": jti, "iat": now, "exp": now + 60,
        }),
        &jsonwebtoken::EncodingKey::from_ec_pem(ID_TOKEN_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}

// r[verify oidc.provider.client-credentials]
#[tokio::test(flavor = "multi_thread")]
async fn bound_clients_get_service_tokens_with_private_key_jwt() {
    let world = world().await;
    let app = &world.app;
    let principal = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{principal}"),
        Some(json!({"kind": "service"})),
    )
    .await;
    let robot = |service_subject: Option<uuid::Uuid>| {
        json!({
            "kind": "confidential",
            "redirect_uris": ["https://robot.example/unused"],
            "audience": "robot-api",
            "service_subject": service_subject,
            "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "kid": "robot-key", "alg": "ES256", "x": KEY_X, "y": KEY_Y}]},
        })
    };
    let registered = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/robot",
            Some(robot(Some(principal))),
        )
        .await;
    assert_eq!(registered.status, StatusCode::OK, "{:?}", registered.body);

    let grant = |assertion: String| async move {
        app.send_form(
            "/v1/oauth2/token",
            &[],
            &[
                ("grant_type", "client_credentials"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", &assertion),
            ],
        )
        .await
    };
    let tokens = grant(assertion("robot", "jti-1")).await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    assert!(tokens.body.get("refresh_token").is_none());
    assert!(tokens.body.get("id_token").is_none());
    let claims =
        konklav_token::decode_claims_unverified(tokens.body["access_token"].as_str().unwrap())
            .unwrap();
    assert_eq!(claims.sub.to_string(), principal.to_string());
    assert_eq!(claims.aud, "robot-api");
    assert_eq!(claims.amr, ["sk"]);

    let replayed = grant(assertion("robot", "jti-1")).await;
    assert_eq!(
        replayed.body["error"], "invalid_client",
        "each jti works once"
    );
    let forged = grant(assertion("console", "jti-2")).await;
    assert_eq!(
        forged.body["error"], "invalid_client",
        "console has no keys"
    );

    // Unbinding the principal ends client credentials.
    app.control(Method::PUT, "/v1/oidc/clients/robot", Some(robot(None)))
        .await;
    let unbound = grant(assertion("robot", "jti-3")).await;
    assert_eq!(unbound.body["error"], "unauthorized_client");
    let human = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/robot",
            Some(robot(Some(uuid::Uuid::parse_str(&world.subject).unwrap()))),
        )
        .await;
    assert_eq!(human.code(), "INVALID_REQUEST", "only service principals");
}

// r[verify oidc.provider.revocation]
#[tokio::test(flavor = "multi_thread")]
async fn clients_revoke_their_tokens() {
    let world = world().await;
    let app = &world.app;
    let code = authorize(&world, &[]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    let refresh = tokens.body["refresh_token"].as_str().unwrap();
    for token in ["not-a-token", refresh] {
        let revoked = app
            .send_form(
                "/v1/oauth2/revoke",
                &[("authorization", &basic(&world.secret))],
                &[("token", token)],
            )
            .await;
        assert_eq!(revoked.status, StatusCode::OK);
    }
    let access = tokens.body["access_token"].as_str().unwrap();
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.status, StatusCode::UNAUTHORIZED, "the session ended");
    let refreshed = app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic(&world.secret))],
            &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
        )
        .await;
    assert_eq!(refreshed.body["error"], "invalid_grant");
}

// r[verify oidc.provider.logout]
#[tokio::test(flavor = "multi_thread")]
async fn logout_ends_the_sign_in_and_notifies_clients() {
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backchannel = format!("http://{}/logout", listener.local_addr().unwrap());
    let sink = received.clone();
    let rp = axum::Router::new().route(
        "/logout",
        axum::routing::post(
            move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
                let sink = sink.clone();
                async move {
                    sink.lock().unwrap().push(form["logout_token"].clone());
                    StatusCode::OK
                }
            },
        ),
    );
    tokio::spawn(async move { axum::serve(listener, rp).await.unwrap() });

    let world = world().await;
    let app = &world.app;
    let updated = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/console",
            Some(json!({
                "kind": "confidential",
                "redirect_uris": [REDIRECT],
                "scopes": ["openid", "email", "groups", "tenant"],
                "audience": "console",
                "visible_groups": ["ops-*"],
                "post_logout_redirect_uris": ["https://console.example/bye"],
                "backchannel_logout_uri": backchannel,
            })),
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{:?}", updated.body);
    let code = authorize(&world, &[]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    let id_token = tokens.body["id_token"].as_str().unwrap();
    let sid = id_token_claims(app, id_token).await["sid"].clone();

    let unregistered = app
        .send(
            Method::GET,
            &format!("/v1/oauth2/logout?id_token_hint={id_token}&post_logout_redirect_uri=https://evil.example/"),
            &[],
            None,
        )
        .await;
    assert_eq!(unregistered.code(), "INVALID_REQUEST");
    let out = app
        .send(
            Method::GET,
            &format!(
                "/v1/oauth2/logout?id_token_hint={id_token}&post_logout_redirect_uri=https://console.example/bye&state=s1"
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{:?}", out.body);
    assert_eq!(location(&out), "https://console.example/bye?state=s1");

    // The login application's sign-in ended too.
    let auth = format!("Bearer {}", world.login_token);
    let own = app
        .send(
            Method::POST,
            "/v1/sign-out",
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(own.code(), "SESSION_ENDED");

    let http = reqwest::Client::new();
    let tried = konklav_server::oidc::deliver_logouts(&app.state, &http)
        .await
        .unwrap();
    assert_eq!(tried, 1);
    let tokens = received.lock().unwrap().clone();
    assert_eq!(tokens.len(), 1);
    let header = jsonwebtoken::decode_header(&tokens[0]).unwrap();
    assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
    let claims = jsonwebtoken::dangerous::insecure_decode::<Value>(&tokens[0])
        .unwrap()
        .claims;
    assert_eq!(claims["aud"], "console");
    assert_eq!(claims["sid"], sid);
    assert!(claims["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
    assert_eq!(
        konklav_server::oidc::deliver_logouts(&app.state, &http)
            .await
            .unwrap(),
        0,
        "delivered once"
    );
}

// r[verify oidc.provider.client-audience]
#[tokio::test(flavor = "multi_thread")]
async fn clients_cannot_take_konklavs_own_audience() {
    let world = world().await;
    let registered = world
        .app
        .control(
            Method::PUT,
            "/v1/oidc/clients/sneaky",
            Some(json!({
                "kind": "confidential",
                "redirect_uris": [REDIRECT],
                "audience": common::AUDIENCE,
                "id_token_alg": "EdDSA",
            })),
        )
        .await;
    assert_eq!(
        registered.code(),
        "INVALID_REQUEST",
        "{:?}",
        registered.body
    );
    assert!(
        registered.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("audience"),
        "{:?}",
        registered.body
    );
}

// r[verify oidc.provider.code-flow]
// r[verify oidc.provider.code-reuse]
#[tokio::test(flavor = "multi_thread")]
async fn a_reused_code_fails_and_revokes_what_it_issued() {
    let world = world().await;
    let app = &world.app;
    let code = authorize(&world, &[]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);

    let replayed = exchange(&world, &code, VERIFIER).await;
    assert_eq!(replayed.body["error"], "invalid_grant");

    let refresh = tokens.body["refresh_token"].as_str().unwrap();
    let refreshed = app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic(&world.secret))],
            &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
        )
        .await;
    assert_eq!(
        refreshed.body["error"], "invalid_grant",
        "{:?}",
        refreshed.body
    );
    let access = tokens.body["access_token"].as_str().unwrap();
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.code(), "SESSION_ENDED", "{:?}", info.body);
}

/// Starts a request, returning the login request id and the browser's
/// cookie.
async fn start(world: &World, extra: &[(&str, &str)]) -> (String, String) {
    let started = world
        .app
        .send(Method::GET, &authorize_uri(extra), &[], None)
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
    let request = query(&location(&started))["login_request"].clone();
    let browser = cookie(&started, "__Host-konklav_authorize").unwrap();
    (request, browser)
}

/// Answers a login request as the login application: `accept` with
/// `token`, or `reject` with a body.
async fn answer(
    world: &World,
    request: &str,
    verb: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> common::Reply {
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers = vec![("origin", ORIGIN), ("x-konklav-client", "web")];
    if let Some(auth) = &auth {
        headers.push(("authorization", auth));
    }
    world
        .app
        .send(
            Method::POST,
            &format!("/v1/oauth2/login-requests/{request}/{verb}"),
            &headers,
            body,
        )
        .await
}

/// Follows an answer's `redirect_to` in the starting browser, returning
/// the query the client receives.
async fn resume(world: &World, answered: &common::Reply, browser: &str) -> HashMap<String, String> {
    let resume = answered.body["redirect_to"].as_str().unwrap();
    let resumed = world
        .app
        .send(
            Method::GET,
            resume.trim_start_matches(ISSUER),
            &[("cookie", browser)],
            None,
        )
        .await;
    assert_eq!(resumed.status, StatusCode::SEE_OTHER, "{:?}", resumed.body);
    let back = location(&resumed);
    assert!(back.starts_with(REDIRECT), "{back}");
    query(&back)
}

// r[verify oidc.provider.scopes]
#[tokio::test(flavor = "multi_thread")]
async fn scopes_the_client_may_not_have_are_dropped() {
    let world = world().await;
    let code = authorize(&world, &[("scope", "openid email address admin email")]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    assert_eq!(tokens.body["scope"], "openid email");
}

// r[verify oidc.provider.prompt]
// r[verify oidc.provider.login-refusal]
#[tokio::test(flavor = "multi_thread")]
async fn login_applications_see_the_prompt_and_can_refuse() {
    let world = world().await;
    let (request, browser) = start(
        &world,
        &[("prompt", "none"), ("login_hint", "ada@example.com")],
    )
    .await;
    let viewed = world
        .app
        .send(
            Method::GET,
            &format!("/v1/oauth2/login-requests/{request}"),
            &[],
            None,
        )
        .await;
    assert_eq!(viewed.body["prompt"], "none");
    assert_eq!(viewed.body["login_hint"], "ada@example.com");

    let unknown = answer(
        &world,
        &request,
        "reject",
        None,
        Some(json!({"error": "nope"})),
    )
    .await;
    assert_eq!(unknown.code(), "INVALID_REQUEST");
    let refused = answer(
        &world,
        &request,
        "reject",
        None,
        Some(json!({"error": "login_required"})),
    )
    .await;
    assert_eq!(refused.status, StatusCode::OK, "{:?}", refused.body);
    let again = answer(&world, &request, "accept", Some(&world.login_token), None).await;
    assert_eq!(
        again.code(),
        "CONFLICT",
        "a refused request can't be accepted"
    );
    let back = resume(&world, &refused, &browser).await;
    assert_eq!(back["error"], "login_required");
    assert_eq!(back["state"], "client-state");
    assert_eq!(back["iss"], ISSUER);
    assert!(!back.contains_key("code"));

    // `prompt=login` takes a sign-in from after the request started.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (request, browser) = start(&world, &[("prompt", "login")]).await;
    let stale = answer(&world, &request, "accept", Some(&world.login_token), None).await;
    assert_eq!(stale.code(), "FORBIDDEN", "{:?}", stale.body);
    let fresh = world.app.login("ada@example.com", PASSWORD).await;
    let fresh = fresh.body["access_token"].as_str().unwrap();
    let accepted = answer(&world, &request, "accept", Some(fresh), None).await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    assert!(
        resume(&world, &accepted, &browser)
            .await
            .contains_key("code")
    );
}

// r[verify oidc.provider.code-flow]
#[tokio::test(flavor = "multi_thread")]
async fn confidential_clients_may_be_registered_without_pkce() {
    let world = world().await;
    let app = &world.app;
    let public = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/spa",
            Some(json!({
                "kind": "public",
                "redirect_uris": [REDIRECT],
                "audience": "spa",
                "require_pkce": false,
            })),
        )
        .await;
    assert_eq!(public.code(), "INVALID_REQUEST", "{:?}", public.body);

    let definition = |require_pkce| {
        json!({
            "kind": "confidential",
            "redirect_uris": [REDIRECT],
            "scopes": ["openid", "email", "groups", "tenant"],
            "audience": "console",
            "visible_groups": ["ops-*"],
            "require_pkce": require_pkce,
        })
    };
    let relaxed = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/console",
            Some(definition(false)),
        )
        .await;
    assert_eq!(relaxed.status, StatusCode::OK, "{:?}", relaxed.body);
    let without = [("code_challenge", ""), ("code_challenge_method", "")];
    let code = authorize(&world, &without).await;
    let downgraded = exchange(&world, &code, VERIFIER).await;
    assert_eq!(
        downgraded.body["error"], "invalid_grant",
        "a verifier without a challenge"
    );
    let code = authorize(&world, &without).await;
    let tokens = app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic(&world.secret))],
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
            ],
        )
        .await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    // A client that sends a challenge is still held to it.
    let code = authorize(&world, &[]).await;
    let tokens = app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic(&world.secret))],
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
            ],
        )
        .await;
    assert_eq!(tokens.body["error"], "invalid_grant");

    app.control(
        Method::PUT,
        "/v1/oidc/clients/console",
        Some(definition(true)),
    )
    .await;
    let started = app
        .send(Method::GET, &authorize_uri(&without), &[], None)
        .await;
    assert_eq!(query(&location(&started))["error"], "invalid_request");
}

// r[verify oidc.provider.code-flow]
#[tokio::test(flavor = "multi_thread")]
async fn authorization_requests_can_be_posted() {
    let world = world().await;
    let form = authorize_uri(&[]);
    let (_, query_string) = form.split_once('?').unwrap();
    let pairs: Vec<(String, String)> = reqwest::Url::parse(&format!("http://x/?{query_string}"))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let started = world
        .app
        .send_form("/v1/oauth2/authorize", &[], &pairs)
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
    assert!(location(&started).starts_with(LOGIN_URL));
}

// r[verify oidc.provider.userinfo]
// r[verify oidc.provider.token-errors]
#[tokio::test(flavor = "multi_thread")]
async fn userinfo_and_token_errors_follow_the_oauth_challenges() {
    let world = world().await;
    let app = &world.app;
    let code = authorize(&world, &[]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    assert_eq!(
        tokens.headers[header::CACHE_CONTROL],
        "no-store",
        "token responses aren't cached"
    );
    let access = tokens.body["access_token"].as_str().unwrap();
    let in_body = app
        .send_form("/v1/oauth2/userinfo", &[], &[("access_token", access)])
        .await;
    assert_eq!(in_body.status, StatusCode::OK, "{:?}", in_body.body);
    assert_eq!(in_body.body["sub"], world.subject);

    let missing = app
        .send(Method::GET, "/v1/oauth2/userinfo", &[], None)
        .await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert!(
        missing.headers[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .starts_with("Bearer")
    );

    let wrong = app
        .send_form(
            "/v1/oauth2/token",
            &[("authorization", &basic("not the secret"))],
            &[("grant_type", "refresh_token"), ("refresh_token", "x")],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["error"], "invalid_client");
    assert!(
        wrong.headers[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .starts_with("Basic")
    );
}

// r[verify oidc.provider.algorithms]
#[tokio::test(flavor = "multi_thread")]
async fn clients_can_get_rs256_id_tokens_when_an_rsa_key_is_configured() {
    let weak = provider().with_rsa_pem(include_str!("fixtures/weak-rsa-key.pem"));
    assert!(weak.is_err(), "a 1024-bit key is refused");
    let not_rsa = provider().with_rsa_pem(ID_TOKEN_KEY);
    assert!(not_rsa.is_err(), "a P-256 key is refused");

    // Without an RSA key, RS256 is neither offered nor registrable.
    let world = world().await;
    let document = world
        .app
        .send(Method::GET, "/.well-known/openid-configuration", &[], None)
        .await;
    assert_eq!(
        document.body["id_token_signing_alg_values_supported"],
        json!(["ES256", "EdDSA"])
    );
    let definition = json!({
        "kind": "confidential",
        "redirect_uris": [REDIRECT],
        "scopes": ["openid", "email", "groups", "tenant"],
        "audience": "console",
        "visible_groups": ["ops-*"],
        "id_token_alg": "RS256",
    });
    let refused = world
        .app
        .control(
            Method::PUT,
            "/v1/oidc/clients/console",
            Some(definition.clone()),
        )
        .await;
    assert_eq!(refused.code(), "INVALID_REQUEST", "{:?}", refused.body);

    let world = world_with(
        provider()
            .with_rsa_pem(include_str!("fixtures/id-token-rsa-key.pem"))
            .unwrap(),
    )
    .await;
    let app = &world.app;
    let document = app
        .send(Method::GET, "/.well-known/openid-configuration", &[], None)
        .await;
    assert_eq!(
        document.body["id_token_signing_alg_values_supported"],
        json!(["ES256", "EdDSA", "RS256"])
    );
    let registered = app
        .control(Method::PUT, "/v1/oidc/clients/console", Some(definition))
        .await;
    assert_eq!(registered.status, StatusCode::OK, "{:?}", registered.body);

    let code = authorize(&world, &[]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    let id_token = tokens.body["id_token"].as_str().unwrap();
    let header = jsonwebtoken::decode_header(id_token).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    let jwks: Value = app
        .send(Method::GET, "/.well-known/jwks.json", &[], None)
        .await
        .body;
    let rsa = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kty"] == "RSA")
        .expect("the RSA key is published");
    assert_eq!(rsa["alg"], "RS256");
    assert_eq!(header.kid.as_deref(), rsa["kid"].as_str());
    let jwk: Jwk = serde_json::from_value(rsa.clone()).unwrap();
    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&["console"]);
    validation.set_issuer(&[ISSUER]);
    let claims =
        jsonwebtoken::decode::<Value>(id_token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation)
            .unwrap()
            .claims;
    assert_eq!(claims["sub"], world.subject);
    assert_eq!(claims["nonce"], "client-nonce");
}

// r[verify oidc.provider.claims]
#[tokio::test(flavor = "multi_thread")]
async fn scope_claims_come_from_any_of_the_subjects_credentials() {
    let world = world().await;
    let app = &world.app;
    let added = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/credentials", world.subject),
            Some(json!({"kind": "phone_otp", "identifier": "+46700000000"})),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.body);
    // Signed in with the password, the phone number still comes along.
    let code = authorize(&world, &[("scope", "openid email phone")]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    let access = tokens.body["access_token"].as_str().unwrap();
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.body["phone_number"], "+46700000000", "{:?}", info.body);
    assert_eq!(info.body["phone_number_verified"], true);
    assert_eq!(info.body["email"], "ada@example.com");
}

/// What the fake claims hook answers.
#[derive(Clone, Copy)]
enum HookAnswer {
    Profile,
    Missing,
    Broken,
}

struct FakeHook {
    url: String,
    answer: std::sync::Arc<std::sync::Mutex<HookAnswer>>,
    /// The signed requests received.
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl FakeHook {
    async fn start() -> Self {
        use axum::routing::post;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/claims", listener.local_addr().unwrap());
        let answer = std::sync::Arc::new(std::sync::Mutex::new(HookAnswer::Profile));
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (answering, recording) = (answer.clone(), requests.clone());
        let router = axum::Router::new().route(
            "/claims",
            post(move |body: String| {
                recording.lock().unwrap().push(body);
                let answer = *answering.lock().unwrap();
                async move {
                    use axum::response::IntoResponse;
                    match answer {
                        // An address and a department too, which the hook
                        // may not supply here.
                        HookAnswer::Profile => axum::Json(json!({
                            "name": "Ada Lovelace",
                            "locale": "en-GB",
                            "email": "someone-else@example.com",
                            "department": "engines",
                        }))
                        .into_response(),
                        HookAnswer::Missing => StatusCode::NOT_FOUND.into_response(),
                        HookAnswer::Broken => StatusCode::BAD_GATEWAY.into_response(),
                    }
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            url,
            answer,
            requests,
        }
    }

    fn provider(
        &self,
        on_failure: konklav_server::config::ClaimsHookFailure,
        ttl: u32,
    ) -> OpenIdProvider {
        let mut provider = provider();
        provider.claims_hook = Some(
            konklav_server::claims_hook::ClaimsHook::from_config(
                &konklav_server::config::ClaimsHook {
                    url: self.url.clone(),
                    scopes: HashMap::from([
                        ("profile".into(), vec!["name".into(), "locale".into()]),
                        ("employee".into(), vec!["department".into()]),
                    ]),
                    timeout_ms: 1000,
                    on_failure,
                    cache_ttl_seconds: ttl,
                    cache_entries: 100,
                },
            )
            .unwrap(),
        );
        provider
    }

    fn calls(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

async fn userinfo_for(world: &World, scope: &str) -> common::Reply {
    let code = authorize(world, &[("scope", scope)]).await;
    let tokens = exchange(world, &code, VERIFIER).await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    let access = tokens.body["access_token"].as_str().unwrap();
    world
        .app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await
}

// r[verify oidc.provider.claims-hook]
// r[verify oidc.provider.claims-hook.request]
// r[verify oidc.provider.claims-hook.scopes]
#[tokio::test(flavor = "multi_thread")]
async fn the_claims_hook_serves_profile_claims_in_userinfo() {
    use konklav_server::config::ClaimsHookFailure;
    let hook = FakeHook::start().await;
    let world = world_with(hook.provider(ClaimsHookFailure::Omit, 0)).await;
    let app = &world.app;

    let discovery = app
        .send(Method::GET, "/.well-known/openid-configuration", &[], None)
        .await;
    let listed = |field: &str, value: &str| {
        discovery.body[field]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == value)
    };
    assert!(listed("scopes_supported", "profile"));
    assert!(listed("claims_supported", "name"));

    // Without a hook scope granted, the hook isn't asked.
    let info = userinfo_for(&world, "openid email").await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert!(info.body.get("name").is_none());
    assert_eq!(hook.calls(), 0);

    let code = authorize(&world, &[("scope", "openid email profile employee")]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    let id = id_token_claims(app, tokens.body["id_token"].as_str().unwrap()).await;
    assert!(id.get("name").is_none(), "ID tokens never ask the hook");
    assert_eq!(hook.calls(), 0);
    let access = tokens.body["access_token"].as_str().unwrap();
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert_eq!(info.body["name"], "Ada Lovelace");
    assert_eq!(info.body["locale"], "en-GB");
    assert_eq!(
        info.body["email"], "ada@example.com",
        "Konklav's own claims win"
    );
    assert!(
        info.body.get("department").is_none(),
        "the client wasn't granted the employee scope"
    );

    // The request is signed with the ID-token key, for the hook.
    let request = hook.requests.lock().unwrap()[0].clone();
    let header = jsonwebtoken::decode_header(&request).unwrap();
    assert_eq!(header.typ.as_deref(), Some("konklav-claims-request+jwt"));
    let jwks: Value = app
        .send(Method::GET, "/.well-known/jwks.json", &[], None)
        .await
        .body;
    let ec = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == header.kid.as_deref().unwrap())
        .unwrap();
    let jwk: Jwk = serde_json::from_value(ec.clone()).unwrap();
    let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_audience(&[&hook.url]);
    validation.set_issuer(&[ISSUER]);
    let claims =
        jsonwebtoken::decode::<Value>(&request, &DecodingKey::from_jwk(&jwk).unwrap(), &validation)
            .unwrap()
            .claims;
    assert_eq!(claims["sub"], world.subject);
    assert_eq!(claims["client_id"], "console");
    assert_eq!(claims["scopes"], json!(["profile"]));
    assert_eq!(claims["claims"], json!(["name", "locale"]));
    assert!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap() <= 60);

    // 404 means no profile.
    *hook.answer.lock().unwrap() = HookAnswer::Missing;
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert!(info.body.get("name").is_none());
}

// r[verify oidc.provider.claims-hook.failure]
#[tokio::test(flavor = "multi_thread")]
async fn claims_hook_failures_omit_or_refuse_as_configured() {
    use konklav_server::config::ClaimsHookFailure;
    let hook = FakeHook::start().await;
    *hook.answer.lock().unwrap() = HookAnswer::Broken;
    let world = world_with(hook.provider(ClaimsHookFailure::Omit, 0)).await;
    let info = userinfo_for(&world, "openid email profile").await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert!(info.body.get("name").is_none());
    assert_eq!(info.body["email"], "ada@example.com");

    let world = world_with(hook.provider(ClaimsHookFailure::Fail, 0)).await;
    let info = userinfo_for(&world, "openid email profile").await;
    assert_eq!(
        info.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{:?}",
        info.body
    );
}

// r[verify oidc.provider.claims-hook.cache]
#[tokio::test(flavor = "multi_thread")]
async fn claims_hook_answers_are_cached_for_their_ttl() {
    use konklav_server::config::ClaimsHookFailure;
    let hook = FakeHook::start().await;
    let world = world_with(hook.provider(ClaimsHookFailure::Omit, 60)).await;
    let code = authorize(&world, &[("scope", "openid profile")]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    let access = tokens.body["access_token"].as_str().unwrap();
    for _ in 0..3 {
        let info = world
            .app
            .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
            .await;
        assert_eq!(info.body["name"], "Ada Lovelace");
    }
    assert_eq!(hook.calls(), 1, "answered from memory after the first call");
}

// r[verify oidc.provider.claims-parameter]
#[tokio::test(flavor = "multi_thread")]
async fn clients_can_ask_for_single_claims() {
    use konklav_server::config::ClaimsHookFailure;
    let hook = FakeHook::start().await;
    let world = world_with(hook.provider(ClaimsHookFailure::Omit, 0)).await;
    let app = &world.app;
    let discovery = app
        .send(Method::GET, "/.well-known/openid-configuration", &[], None)
        .await;
    assert_eq!(discovery.body["claims_parameter_supported"], true);

    // Only `openid`: the claims come one by one. `department` needs the
    // employee scope, which the client isn't registered for, and the hook's
    // `name` isn't served in ID tokens.
    let claims = json!({
        "userinfo": {"name": {"essential": true}, "department": null, "unknown": null},
        "id_token": {"email": {"essential": true}, "name": null},
    })
    .to_string();
    let code = authorize(&world, &[("scope", "openid"), ("claims", &claims)]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    assert_eq!(tokens.body["scope"], "openid");
    let id = id_token_claims(app, tokens.body["id_token"].as_str().unwrap()).await;
    assert_eq!(id["email"], "ada@example.com", "{id:?}");
    assert_eq!(id["email_verified"], false);
    assert!(id.get("name").is_none(), "{id:?}");
    assert!(id.get("groups").is_none(), "{id:?}");
    assert_eq!(hook.calls(), 0, "issuing tokens never asks the hook");

    let access = tokens.body["access_token"].as_str().unwrap();
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert_eq!(info.body["name"], "Ada Lovelace");
    assert!(
        info.body.get("locale").is_none(),
        "only the claim asked for"
    );
    assert!(info.body.get("department").is_none());
    assert!(
        info.body.get("email").is_none(),
        "email was asked for in the ID token"
    );
    let request = hook.requests.lock().unwrap()[0].clone();
    let request = jsonwebtoken::dangerous::insecure_decode::<Value>(&request)
        .unwrap()
        .claims;
    assert_eq!(request["scopes"], json!([]));
    assert_eq!(request["claims"], json!(["name"]));

    // Konklav's own claims work one by one in userinfo too.
    let claims = json!({"userinfo": {"email": null}}).to_string();
    let code = authorize(&world, &[("scope", "openid"), ("claims", &claims)]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    let access = tokens.body["access_token"].as_str().unwrap();
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.body["email"], "ada@example.com", "{:?}", info.body);
    assert!(info.body.get("groups").is_none());
}

// r[verify federation.pass-claims]
#[tokio::test(flavor = "multi_thread")]
async fn passed_claims_reach_clients_through_userinfo() {
    use konklav_server::config::ClaimsHookFailure;
    let hook = FakeHook::start().await;
    let provider = hook.provider(ClaimsHookFailure::Omit, 0);
    let app = TestApp::with_auth(|auth| {
        auth.oidc = Some(provider);
        auth.identity_providers = konklav_server::federation::Providers::from_settings([
            konklav_server::federation::Settings {
                id: "ops".into(),
                pass_claims: [(
                    "profile".to_owned(),
                    vec!["name".to_owned(), "nickname".to_owned()],
                )]
                .into(),
                ..Default::default()
            },
        ]);
    })
    .await;
    let world = world_in(app).await;
    let app = &world.app;
    // As a federated login would have kept them on the login session.
    let sid = konklav_token::decode_claims_unverified(&world.login_token)
        .unwrap()
        .sid;
    let mut conn = app.db.pool().get().await.unwrap();
    konklav_store::sessions::set_identity_claims(
        &mut conn,
        sid,
        &json!({"profile": {"name": "Ada from upstream", "nickname": "Ada"}}),
    )
    .await
    .unwrap();
    drop(conn);

    let discovery = app
        .send(Method::GET, "/.well-known/openid-configuration", &[], None)
        .await;
    assert!(
        discovery.body["claims_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "nickname")
    );

    let info = userinfo_for(&world, "openid profile").await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert_eq!(info.body["name"], "Ada Lovelace", "the hook's value wins");
    assert_eq!(info.body["nickname"], "Ada");

    // One by one with the claims parameter, without the scope.
    let claims = json!({"userinfo": {"nickname": null}}).to_string();
    let code = authorize(&world, &[("scope", "openid"), ("claims", &claims)]).await;
    let tokens = exchange(&world, &code, VERIFIER).await;
    let access = tokens.body["access_token"].as_str().unwrap();
    let info = app
        .with_bearer(Method::GET, "/v1/oauth2/userinfo", access)
        .await;
    assert_eq!(info.body["nickname"], "Ada", "{:?}", info.body);
    assert!(info.body.get("name").is_none());

    // Without the scope or a request, nothing passes.
    let info = userinfo_for(&world, "openid email").await;
    assert!(info.body.get("nickname").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn operators_read_registered_clients_without_their_secrets() {
    let world = world().await;
    let app = &world.app;
    let list = app.control(Method::GET, "/v1/oidc/clients", None).await;
    assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
    let ids: Vec<&str> = list
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|client| client["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"console"), "{ids:?}");

    let client = app
        .control(Method::GET, "/v1/oidc/clients/console", None)
        .await;
    assert_eq!(client.status, StatusCode::OK, "{:?}", client.body);
    assert_eq!(client.body["kind"], "confidential");
    assert_eq!(client.body["has_secret"], true);
    assert!(client.body["disabled_at"].is_null());
    assert!(
        !client.body.to_string().contains(&world.secret),
        "the secret is never returned"
    );

    let unknown = app
        .control(Method::GET, "/v1/oidc/clients/nobody", None)
        .await;
    assert_eq!(unknown.code(), "NOT_FOUND");
}

// --- DPoP ------------------------------------------------------------------------

const TOKEN_URL: &str = "https://auth.example/v1/oauth2/token";
const USERINFO_URL: &str = "https://auth.example/v1/oauth2/userinfo";

/// Registers a public client `spa` that may refresh.
async fn register_spa(world: &World, extra: Value) {
    let mut definition = json!({
        "kind": "public",
        "redirect_uris": [REDIRECT],
        "audience": "spa",
    });
    for (key, value) in extra.as_object().unwrap() {
        definition[key] = value.clone();
    }
    let registered = world
        .app
        .control(Method::PUT, "/v1/oidc/clients/spa", Some(definition))
        .await;
    assert_eq!(registered.status, StatusCode::OK, "{:?}", registered.body);
}

/// Exchanges `code` for `spa`, with a proof from `key` when given.
async fn spa_tokens(world: &World, code: &str, key: Option<&DpopKey>) -> common::Reply {
    let proof = key.map(|key| key.proof("POST", TOKEN_URL, None));
    let headers: Vec<(&str, &str)> = proof.iter().map(|p| ("dpop", p.as_str())).collect();
    world
        .app
        .send_form(
            "/v1/oauth2/token",
            &headers,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", "spa"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await
}

async fn spa_refresh(world: &World, refresh: &str, proof: Option<&str>) -> common::Reply {
    let headers: Vec<(&str, &str)> = proof.iter().map(|p| ("dpop", *p)).collect();
    world
        .app
        .send_form(
            "/v1/oauth2/token",
            &headers,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", "spa"),
                ("refresh_token", refresh),
            ],
        )
        .await
}

async fn userinfo_with(world: &World, headers: &[(&str, &str)]) -> common::Reply {
    world
        .app
        .send(Method::GET, "/v1/oauth2/userinfo", headers, None)
        .await
}

fn challenge_of(reply: &common::Reply) -> Vec<String> {
    reply
        .headers
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

// r[verify oidc.provider.dpop.token]
// r[verify token.dpop.cnf]
// r[verify token.dpop.scheme]
// r[verify token.dpop.replay]
// r[verify oidc.provider.dpop.errors]
// r[verify oidc.provider.dpop.htu]
#[tokio::test(flavor = "multi_thread")]
async fn a_proof_at_the_token_endpoint_binds_the_clients_tokens_to_its_key() {
    let world = world().await;
    register_spa(&world, json!({})).await;
    let key = DpopKey::new(1);
    let code = authorize(&world, &[("client_id", "spa"), ("scope", "openid")]).await;
    let tokens = spa_tokens(&world, &code, Some(&key)).await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    assert_eq!(tokens.body["token_type"], "DPoP");
    let access = tokens.body["access_token"].as_str().unwrap();
    let claims = konklav_token::decode_claims_unverified(access).unwrap();
    assert_eq!(claims.cnf.unwrap().jkt, key.jkt());

    // The session records the key, for operators.
    let sessions = world
        .app
        .control(
            Method::GET,
            &format!("/v1/sessions?subject={}&active=true", world.subject),
            None,
        )
        .await;
    let bound: Vec<_> = sessions.body["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["dpop_jkt"].as_str())
        .collect();
    assert_eq!(bound, [key.jkt()]);

    // UserInfo takes the token only under DPoP, with a proof for itself.
    let dpop_auth = format!("DPoP {access}");
    let proof = key.proof("GET", USERINFO_URL, Some(access));
    let served = userinfo_with(&world, &[("authorization", &dpop_auth), ("dpop", &proof)]).await;
    assert_eq!(served.status, StatusCode::OK, "{:?}", served.body);
    assert_eq!(served.body["sub"], world.subject);

    let refused = |reply: &common::Reply| {
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{:?}", reply.body);
        assert_eq!(
            challenge_of(reply),
            ["DPoP error=\"invalid_dpop_proof\", algs=\"ES256 EdDSA\""]
        );
    };
    // The same proof again.
    refused(&userinfo_with(&world, &[("authorization", &dpop_auth), ("dpop", &proof)]).await);
    // As a bearer token, or without a proof.
    let bearer = format!("Bearer {access}");
    refused(&userinfo_with(&world, &[("authorization", &bearer)]).await);
    refused(&userinfo_with(&world, &[("authorization", &dpop_auth)]).await);
    // A proof for another URL, another token, or from another key.
    let elsewhere = key.proof(
        "GET",
        "https://elsewhere.example/v1/oauth2/userinfo",
        Some(access),
    );
    refused(
        &userinfo_with(
            &world,
            &[("authorization", &dpop_auth), ("dpop", &elsewhere)],
        )
        .await,
    );
    let other_token = key.proof("GET", USERINFO_URL, Some("another token"));
    refused(
        &userinfo_with(
            &world,
            &[("authorization", &dpop_auth), ("dpop", &other_token)],
        )
        .await,
    );
    let other_key = DpopKey::new(2).proof("GET", USERINFO_URL, Some(access));
    refused(
        &userinfo_with(
            &world,
            &[("authorization", &dpop_auth), ("dpop", &other_key)],
        )
        .await,
    );
    // A proof whose claims are fine but which is too old.
    let stale = key.sign(&json!({
        "jti": "stale",
        "htm": "GET",
        "htu": USERINFO_URL,
        "iat": chrono::Utc::now().timestamp() - 120,
        "ath": konklav_token::access_token_hash(access),
    }));
    refused(&userinfo_with(&world, &[("authorization", &dpop_auth), ("dpop", &stale)]).await);

    // A bad proof at the token endpoint is `invalid_dpop_proof`.
    let code = authorize(&world, &[("client_id", "spa"), ("scope", "openid")]).await;
    let wrong_url = key.proof("POST", "https://auth.example/v1/oauth2/revoke", None);
    let bad = world
        .app
        .send_form(
            "/v1/oauth2/token",
            &[("dpop", &wrong_url)],
            &[
                ("grant_type", "authorization_code"),
                ("client_id", "spa"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.body["error"], "invalid_dpop_proof");
}

// r[verify token.refresh.dpop-bound]
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_sessions_refresh_token_needs_a_proof_from_its_key() {
    let world = world().await;
    register_spa(&world, json!({})).await;
    let key = DpopKey::new(1);
    let code = authorize(&world, &[("client_id", "spa"), ("scope", "openid")]).await;
    let tokens = spa_tokens(&world, &code, Some(&key)).await;
    let refresh = tokens.body["refresh_token"].as_str().unwrap().to_owned();

    // Without a proof, or with another key's, the refresh is refused and
    // nothing rotates: the same refresh token still works afterwards.
    let without = spa_refresh(&world, &refresh, None).await;
    assert_eq!(without.status, StatusCode::BAD_REQUEST);
    assert_eq!(without.body["error"], "invalid_dpop_proof");
    let other = DpopKey::new(2).proof("POST", TOKEN_URL, None);
    let stolen = spa_refresh(&world, &refresh, Some(&other)).await;
    assert_eq!(stolen.body["error"], "invalid_dpop_proof");

    let proof = key.proof("POST", TOKEN_URL, None);
    let refreshed = spa_refresh(&world, &refresh, Some(&proof)).await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    assert_eq!(refreshed.body["token_type"], "DPoP");
    let access = refreshed.body["access_token"].as_str().unwrap();
    let claims = konklav_token::decode_claims_unverified(access).unwrap();
    assert_eq!(claims.cnf.unwrap().jkt, key.jkt());
}

// r[verify oidc.provider.dpop.token]
// r[verify token.dpop.binding]
#[tokio::test(flavor = "multi_thread")]
async fn grants_without_a_proof_stay_bearer_tokens_for_good() {
    let world = world().await;
    register_spa(&world, json!({})).await;
    let code = authorize(&world, &[("client_id", "spa"), ("scope", "openid")]).await;
    let tokens = spa_tokens(&world, &code, None).await;
    assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
    assert_eq!(tokens.body["token_type"], "Bearer");
    let access = tokens.body["access_token"].as_str().unwrap();
    assert!(
        konklav_token::decode_claims_unverified(access)
            .unwrap()
            .cnf
            .is_none()
    );

    // A proof at refresh doesn't bind the session after the fact.
    let refresh = tokens.body["refresh_token"].as_str().unwrap();
    let proof = DpopKey::new(1).proof("POST", TOKEN_URL, None);
    let refreshed = spa_refresh(&world, refresh, Some(&proof)).await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    assert_eq!(refreshed.body["token_type"], "Bearer");
    let access = refreshed.body["access_token"].as_str().unwrap();
    assert!(
        konklav_token::decode_claims_unverified(access)
            .unwrap()
            .cnf
            .is_none()
    );

    // A bearer token isn't accepted under the DPoP scheme.
    let auth = format!("DPoP {access}");
    let proof = DpopKey::new(1).proof("GET", USERINFO_URL, Some(access));
    let refused = userinfo_with(&world, &[("authorization", &auth), ("dpop", &proof)]).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
}

// r[verify oidc.provider.dpop.required]
// r[verify oidc.provider.dpop.code-binding]
#[tokio::test(flavor = "multi_thread")]
async fn clients_can_require_dpop_and_codes_can_be_bound_to_a_key() {
    let world = world().await;
    register_spa(&world, json!({"require_dpop": true})).await;
    let read = world
        .app
        .control(Method::GET, "/v1/oidc/clients/spa", None)
        .await;
    assert_eq!(read.body["require_dpop"], true);
    let code = authorize(&world, &[("client_id", "spa"), ("scope", "openid")]).await;
    let refused = spa_tokens(&world, &code, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["error"], "invalid_dpop_proof");

    let key = DpopKey::new(1);
    let jkt = key.jkt();
    let bound = authorize(
        &world,
        &[
            ("client_id", "spa"),
            ("scope", "openid"),
            ("dpop_jkt", &jkt),
        ],
    )
    .await;
    let other = spa_tokens(&world, &bound, Some(&DpopKey::new(2))).await;
    assert_eq!(other.status, StatusCode::BAD_REQUEST);
    assert_eq!(other.body["error"], "invalid_dpop_proof");
    let exchanged = spa_tokens(&world, &bound, Some(&key)).await;
    assert_eq!(exchanged.status, StatusCode::OK, "{:?}", exchanged.body);
    assert_eq!(exchanged.body["token_type"], "DPoP");

    // A malformed `dpop_jkt` is an invalid request.
    let started = world
        .app
        .send(
            Method::GET,
            &authorize_uri(&[("client_id", "spa"), ("dpop_jkt", "not-a-thumbprint")]),
            &[],
            None,
        )
        .await;
    assert_eq!(query(&location(&started))["error"], "invalid_request");
}

// r[verify oidc.provider.dpop.policy]
#[tokio::test(flavor = "multi_thread")]
async fn the_provider_can_require_dpop_of_every_public_client() {
    let mut provider = provider();
    provider.require_dpop = konklav_server::config::DpopRequirement::PublicClients;
    let world = world_with(provider).await;
    register_spa(&world, json!({})).await;

    let code = authorize(&world, &[("client_id", "spa"), ("scope", "openid")]).await;
    let refused = spa_tokens(&world, &code, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["error"], "invalid_dpop_proof");
    let bound = spa_tokens(&world, &code, Some(&DpopKey::new(1))).await;
    assert_eq!(bound.status, StatusCode::OK, "{:?}", bound.body);
    assert_eq!(bound.body["token_type"], "DPoP");

    // A confidential client isn't covered by `public_clients`.
    let code = authorize(&world, &[]).await;
    let confidential = exchange(&world, &code, VERIFIER).await;
    assert_eq!(confidential.status, StatusCode::OK, "{:?}", confidential.body);
    assert_eq!(confidential.body["token_type"], "Bearer");
}
