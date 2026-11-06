//! Sender-constrained tokens for a browser app.
//!
//! A single-page app is a public OIDC client that must use DPoP. It keeps a
//! key the page can't export (here a P-256 key standing in for a
//! non-extractable WebCrypto key), and every token Konklav gives it works
//! only with proofs signed by that key. A relying system, using the Rust
//! relying client, accepts the app's requests with fresh proofs and refuses
//! a replayed proof and the same token sent as a bearer token.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use konklav_authz::{Decision, DenyReason, Requirements};
use konklav_relying::Config;
use konklav_relying_client::{ClientConfig, Presented, RelyingClient, RequestDescriptor};
use konklav_test_support::DpopKey;
use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};

use crate::harness::{Server, Setup};
use crate::{Result, check, fail, step};

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery";
/// The app, which is also its own login page.
const APP: &str = "http://app.example";
const CALLBACK: &str = "http://app.example/callback";
/// The relying system's API, as the app addresses it.
const API_URL: &str = "https://api.example/projects/1";
const VERIFIER: &str = "a-code-verifier-that-is-long-enough-to-be-valid-0123456789";

fn location(reply: &reqwest::Response) -> Result<String> {
    reply
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| {
            fail(format!(
                "{} has no redirect ({})",
                reply.url(),
                reply.status()
            ))
        })
}

fn cookie(reply: &reqwest::Response, name: &str) -> Result<String> {
    reply
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
        .ok_or_else(|| fail(format!("{} sets no {name} cookie", reply.url())))
}

fn query(url: &str, key: &str) -> Result<String> {
    reqwest::Url::parse(url)?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| fail(format!("{url} has no {key}")))
}

/// Starts Konklav as an OpenID provider, with Ada allowed `project:read`
/// and the app registered as a public client that must use DPoP.
async fn konklav(binary: &Path) -> Result<Server> {
    let server = Server::start(&Setup {
        binary: Some(binary.to_owned()),
        login_url: Some(format!("{APP}/sign-in")),
        browser_origins: vec![APP.into()],
        ..Setup::default()
    })
    .await?;
    server
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({"actions": [{"name": "project:read"}]})),
        )
        .await?;
    server
        .control(
            Method::PUT,
            "/v1/tenants/root/roles/reader",
            Some(json!({"policies": [{"action": "project:read", "effect": "allow"}]})),
        )
        .await?;
    let ada = server
        .human(json!({"kind": "password", "identifier": EMAIL, "password": PASSWORD}))
        .await?;
    server
        .control(
            Method::POST,
            &format!("/v1/subjects/{ada}/global-assignments"),
            Some(json!({"role": "reader"})),
        )
        .await?;
    server
        .control(
            Method::PUT,
            "/v1/oidc/clients/spa",
            Some(json!({
                "kind": "public",
                "redirect_uris": [CALLBACK],
                "audience": "api",
                "require_dpop": true,
            })),
        )
        .await?;
    Ok(server)
}

/// The app signs Ada in with the code flow, binding the code to its key,
/// and exchanges it with a proof. Returns the token response.
async fn sign_in(server: &Server, key: &DpopKey) -> Result<Value> {
    let http = &server.http;
    let challenge = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, VERIFIER.as_bytes()),
    );
    let jkt = key.jkt();

    step("the app sends the browser to Konklav, binding the code to its key (dpop_jkt)");
    let authorize = reqwest::Url::parse_with_params(
        &format!("{}/v1/oauth2/authorize", server.subject),
        &[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", CALLBACK),
            ("scope", "openid"),
            ("state", "app-state"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("dpop_jkt", jkt.as_str()),
        ],
    )?;
    let handed_off = http.get(authorize).send().await?;
    let login_page = location(&handed_off)?;
    let browser = cookie(&handed_off, "konklav_authorize")?;
    let request = query(&login_page, "login_request")?;
    println!("    redirected to {login_page}");

    step("the login page signs Ada in and accepts the request");
    let (status, login) = server
        .post(
            "/v1/login/password",
            &json!({"identifier": EMAIL, "password": PASSWORD}),
        )
        .await?;
    check(status.is_success(), || {
        format!("signing in: {status} {login}")
    })?;
    let accepted: Value = http
        .post(format!(
            "{}/v1/oauth2/login-requests/{request}/accept",
            server.subject
        ))
        .bearer_auth(login["access_token"].as_str().unwrap_or_default())
        .header(header::ORIGIN, APP)
        .header("x-konklav-client", "web")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let resume = accepted["redirect_to"]
        .as_str()
        .ok_or_else(|| fail(format!("no redirect in {accepted}")))?;
    let resumed = http
        .get(resume)
        .header(header::COOKIE, &browser)
        .send()
        .await?;
    let code = query(&location(&resumed)?, "code")?;

    let token_url = format!("{}/v1/oauth2/token", server.issuer);
    let exchange = |proof: Option<String>| {
        let mut request = http.post(&token_url).form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "spa"),
            ("code", code.as_str()),
            ("redirect_uri", CALLBACK),
            ("code_verifier", VERIFIER),
        ]);
        if let Some(proof) = proof {
            request = request.header("dpop", proof);
        }
        request.send()
    };

    step("without a proof, the token endpoint refuses the code (the client requires DPoP)");
    let refused = exchange(None).await?;
    let status = refused.status();
    let body: Value = refused.json().await?;
    check(
        status == StatusCode::BAD_REQUEST && body["error"] == "invalid_dpop_proof",
        || format!("expected invalid_dpop_proof, got {status} {body}"),
    )?;
    println!("    {status}: {body}");

    step("with a proof from the app's key, it issues DPoP tokens");
    let tokens: Value = exchange(Some(key.proof("POST", &token_url, None)))
        .await?
        .error_for_status()?
        .json()
        .await?;
    check(tokens["token_type"] == "DPoP", || {
        format!("expected DPoP tokens, got {tokens}")
    })?;
    println!("    token_type {}, bound to {jkt}", tokens["token_type"]);
    Ok(tokens)
}

/// A relying system for the app's audience, following Konklav's feed.
async fn relying_system(server: &Server) -> Result<RelyingClient> {
    let key = server.service_principal(&[]).await?;
    let (key_id, secret) = key
        .split_once('.')
        .ok_or_else(|| fail("malformed secret key"))?;
    let client = RelyingClient::new(ClientConfig {
        relying_url: server.relying.clone(),
        subject_url: server.subject.clone(),
        key_id: key_id.into(),
        secret: secret.into(),
        core: Config {
            issuer: server.issuer.clone(),
            audience: "api".into(),
            ..Config::default()
        },
    });
    // Detached: the background tasks run until the runtime stops.
    drop(client.start());
    for _ in 0..500 {
        if client.is_trusted() {
            return Ok(client);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(fail("the relying client never caught up with the feed"))
}

fn presented(authorization: String, proof: Option<String>) -> Presented {
    Presented {
        authorization,
        dpop: proof,
        request: Some(RequestDescriptor {
            method: "GET".into(),
            url: API_URL.into(),
        }),
    }
}

pub async fn run(binary: &Path) -> Result<()> {
    step("Konklav starts as an OpenID provider; the app is a public client requiring DPoP");
    let server = konklav(binary).await?;
    let key = DpopKey::new(7);
    let tokens = sign_in(&server, &key).await?;
    let access = tokens["access_token"]
        .as_str()
        .ok_or_else(|| fail("no access token"))?;

    step("a relying system decides the app's requests with the relying client");
    let api = relying_system(&server).await?;
    let reading = Requirements {
        global: BTreeSet::from(["project:read".to_owned()]),
        token_kinds: Some(BTreeSet::from([konklav_token::TokenKind::Identity])),
        ..Requirements::default()
    };
    let proof = key.proof("GET", API_URL, Some(access));
    let request = presented(format!("DPoP {access}"), Some(proof));
    let decision = api.decide_request(&request, &reading).await?;
    check(decision == Decision::allow(), || {
        format!("expected allow, got {decision:?}")
    })?;
    println!("    with a fresh proof: {decision:?}");

    let refused = Decision::Deny {
        reason: DenyReason::InvalidDpopProof,
    };
    step("replaying the same request is refused");
    let replayed = api.decide_request(&request, &reading).await?;
    check(replayed == refused, || {
        format!("expected a refusal, got {replayed:?}")
    })?;
    println!("    {replayed:?}");

    step("the token copied off the page and sent as a bearer token is refused");
    let stolen = api
        .decide_request(&presented(format!("Bearer {access}"), None), &reading)
        .await?;
    check(stolen == refused, || {
        format!("expected a refusal, got {stolen:?}")
    })?;
    println!("    {stolen:?}");

    step("the refresh token works only with a proof from the app's key");
    let refresh = tokens["refresh_token"]
        .as_str()
        .ok_or_else(|| fail("no refresh token"))?;
    let token_url = format!("{}/v1/oauth2/token", server.issuer);
    let refresh_with = |proof: Option<String>| {
        let mut request = server.http.post(&token_url).form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "spa"),
            ("refresh_token", refresh),
        ]);
        if let Some(proof) = proof {
            request = request.header("dpop", proof);
        }
        request.send()
    };
    let thief = DpopKey::new(8).proof("POST", &token_url, None);
    let status = refresh_with(Some(thief)).await?.status();
    check(status == StatusCode::BAD_REQUEST, || {
        format!("another key's proof refreshed: {status}")
    })?;
    println!("    with another key's proof: {status}");
    let refreshed: Value = refresh_with(Some(key.proof("POST", &token_url, None)))
        .await?
        .error_for_status()?
        .json()
        .await?;
    check(refreshed["token_type"] == "DPoP", || {
        format!("expected DPoP tokens, got {refreshed}")
    })?;
    println!(
        "    with the app's key: token_type {}",
        refreshed["token_type"]
    );
    Ok(())
}
