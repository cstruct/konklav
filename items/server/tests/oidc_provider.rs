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

async fn world() -> World {
    let provider = OpenIdProvider::from_pem(
        ID_TOKEN_KEY,
        LOGIN_URL.into(),
        format!("{ISSUER}/.well-known/jwks.json"),
    )
    .unwrap();
    let app = TestApp::with_openid_provider(provider).await;
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
                "scopes": ["openid", "email", "groups", "tenant"],
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
    let browser = cookie(&started, "konklav_authorize").unwrap();

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
    let attacker = cookie(&started, "konklav_authorize").unwrap();
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
    assert_eq!(id["email"], "ada@example.com");
    assert_eq!(id["email_verified"], false);
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

    // Codes are single-use.
    let replayed = exchange(&world, &code, VERIFIER).await;
    assert_eq!(replayed.body["error"], "invalid_grant");

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

// r[verify oidc.provider.discovery]
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
        assert_eq!(reply.code(), "INVALID_REQUEST", "{extra:?}");
    }
    // Other problems go back to the client.
    for (extra, error) in [
        (vec![("code_challenge", "")], "invalid_request"),
        (vec![("code_challenge_method", "plain")], "invalid_request"),
        (vec![("scope", "openid admin")], "invalid_scope"),
        (vec![("scope", "email")], "invalid_scope"),
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
    assert_eq!(started.code(), "INVALID_REQUEST");
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
