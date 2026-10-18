//! Konklav as an OpenID provider, driven by an independent client library
//! (`openidconnect`): discovery, the code flow with PKCE, ID-token
//! verification against Konklav's JWKS, userinfo, refresh and revocation.
//! The login hand-off is played in-process, as a login application would.

#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashMap;

use axum::http::{Method, StatusCode, header};
use common::{ORIGIN, TestApp};
use konklav_server::oidc::OpenIdProvider;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreUserInfoClaims,
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use serde_json::json;

const REDIRECT: &str = "https://console.example/callback";
const PASSWORD: &str = "correct horse battery";

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

fn cookie(reply: &common::Reply, name: &str) -> String {
    reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .unwrap()
}

/// Plays the login application for the authorization request at `url`:
/// hands off, accepts with `login_token`, resumes. Returns the redirect to
/// the client.
async fn hand_off(app: &TestApp, base: &str, url: &str, login_token: &str) -> String {
    let started = app
        .send(Method::GET, url.trim_start_matches(base), &[], None)
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
    let request = query(&location(&started))["login_request"].clone();
    let browser = cookie(&started, "konklav_authorize");
    let auth = format!("Bearer {login_token}");
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
    let resumed = app
        .send(
            Method::GET,
            resume.trim_start_matches(base),
            &[("cookie", &browser)],
            None,
        )
        .await;
    location(&resumed)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_standard_client_library_signs_in_through_konklav() {
    let (app, base) = TestApp::serving(|auth, base| {
        auth.oidc = Some(
            OpenIdProvider::from_pem(
                include_str!("fixtures/id-token-key.pem"),
                "https://login.example/".into(),
                format!("{base}/.well-known/jwks.json"),
            )
            .unwrap(),
        );
    })
    .await;
    let subject = app.human("ada@example.com", PASSWORD).await;
    let registered = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/console",
            Some(json!({
                "kind": "confidential",
                "redirect_uris": [REDIRECT],
                "scopes": ["openid", "email"],
                "audience": "console",
            })),
        )
        .await;
    assert_eq!(registered.status, StatusCode::OK, "{:?}", registered.body);
    let secret = app
        .control(Method::POST, "/v1/oidc/clients/console/secret", None)
        .await
        .body["client_secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret_for_revocation = secret.clone();
    let login_token = app.login("ada@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let http = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let metadata =
        CoreProviderMetadata::discover_async(IssuerUrl::new(base.clone()).unwrap(), &http)
            .await
            .expect("the client accepts Konklav's discovery document and keys");
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new("console".into()),
        Some(ClientSecret::new(secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(REDIRECT.into()).unwrap());

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, csrf, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(challenge)
        .url();
    let back = hand_off(&app, &base, url.as_str(), &login_token).await;
    let params = query(&back);
    assert_eq!(&params["state"], csrf.secret());

    let tokens = client
        .exchange_code(AuthorizationCode::new(params["code"].clone()))
        .unwrap()
        .set_pkce_verifier(verifier)
        .request_async(&http)
        .await
        .expect("the code exchange succeeds");
    let id_token = tokens.id_token().expect("an ID token");
    let claims = id_token
        .claims(&client.id_token_verifier(), &nonce)
        .expect("the ID token verifies against Konklav's JWKS");
    assert_eq!(claims.subject().as_str(), subject);
    assert_eq!(claims.email().map(|e| e.as_str()), Some("ada@example.com"));

    let info: CoreUserInfoClaims = client
        .user_info(tokens.access_token().clone(), None)
        .unwrap()
        .request_async(&http)
        .await
        .expect("userinfo answers");
    assert_eq!(info.subject().as_str(), subject);

    let refresh = tokens.refresh_token().expect("a refresh token").clone();
    let refreshed = client
        .exchange_refresh_token(&refresh)
        .unwrap()
        .request_async(&http)
        .await
        .expect("refreshing works");
    let rotated = refreshed
        .refresh_token()
        .expect("a rotated refresh token")
        .clone();
    // The library only revokes over HTTPS, so send its RFC 7009 request
    // directly.
    let revoked = reqwest::Client::new()
        .post(format!("{base}/v1/oauth2/revoke"))
        .basic_auth("console", Some(&secret_for_revocation))
        .form(&[
            ("token", rotated.secret().as_str()),
            ("token_type_hint", "refresh_token"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), reqwest::StatusCode::OK);
    assert!(
        client
            .exchange_refresh_token(&rotated)
            .unwrap()
            .request_async(&http)
            .await
            .is_err(),
        "a revoked refresh token is refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn public_clients_verify_eddsa_id_tokens_with_the_library() {
    let (app, base) = TestApp::serving(|auth, base| {
        auth.oidc = Some(
            OpenIdProvider::from_pem(
                include_str!("fixtures/id-token-key.pem"),
                "https://login.example/".into(),
                format!("{base}/.well-known/jwks.json"),
            )
            .unwrap(),
        );
    })
    .await;
    app.human("ada@example.com", PASSWORD).await;
    let registered = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/spa",
            Some(json!({
                "kind": "public",
                "redirect_uris": [REDIRECT],
                "audience": "spa",
                "id_token_alg": "EdDSA",
            })),
        )
        .await;
    assert_eq!(registered.status, StatusCode::OK, "{:?}", registered.body);
    let login_token = app.login("ada@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let http = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let metadata =
        CoreProviderMetadata::discover_async(IssuerUrl::new(base.clone()).unwrap(), &http)
            .await
            .unwrap();
    let client = CoreClient::from_provider_metadata(metadata, ClientId::new("spa".into()), None)
        .set_redirect_uri(RedirectUrl::new(REDIRECT.into()).unwrap());
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, _, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge)
        .url();
    let back = hand_off(&app, &base, url.as_str(), &login_token).await;
    let tokens = client
        .exchange_code(AuthorizationCode::new(query(&back)["code"].clone()))
        .unwrap()
        .set_pkce_verifier(verifier)
        .request_async(&http)
        .await
        .expect("public clients exchange codes with PKCE alone");
    let verifier = client
        .id_token_verifier()
        .set_allowed_algs([openidconnect::core::CoreJwsSigningAlgorithm::EdDsa]);
    tokens
        .id_token()
        .unwrap()
        .claims(&verifier, &nonce)
        .expect("the EdDSA ID token verifies against Konklav's Ed25519 keys");
}
