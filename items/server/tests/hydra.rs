//! Konklav as a client of an independent OpenID provider, Ory Hydra.
//!
//! Each test starts Hydra in memory on free ports (`hydra` comes from mise),
//! registers Konklav as a Hydra client, and plays Hydra's login and consent
//! application through its admin API. The browser's hops are followed with
//! a cookie-keeping HTTP client; Konklav reaches Hydra's token endpoint and
//! keys over real HTTP. Without `hydra` on the PATH the tests are skipped.

#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use axum::http::{Method, StatusCode, header};
use common::{ISSUER, ORIGIN, TestApp};
use konklav_server::federation::{Providers, Provisioning, Settings};
use konklav_server::oidc::OpenIdProvider;
use serde_json::{Value, json};

const CALLBACK: &str = "https://auth.example/v1/login/oidc/hydra/callback";
const RETURN: &str = "https://app.example/signed-in";
const CLIENT_SECRET: &str = "konklav-client-secret";

struct Hydra {
    process: Child,
    public: String,
    admin: String,
    /// The issuer exactly as Hydra's discovery document names it.
    issuer: String,
}

impl Drop for Hydra {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Starts Hydra, or returns None (skipping the test) without it.
async fn hydra() -> Option<Hydra> {
    let (public_port, admin_port) = (free_port(), free_port());
    let public = format!("http://127.0.0.1:{public_port}");
    let admin = format!("http://127.0.0.1:{admin_port}");
    let spawned = Command::new("hydra")
        .args(["serve", "all", "--dev"])
        .env("DSN", "memory")
        .env("SERVE_PUBLIC_PORT", public_port.to_string())
        .env("SERVE_PUBLIC_HOST", "127.0.0.1")
        .env("SERVE_ADMIN_PORT", admin_port.to_string())
        .env("SERVE_ADMIN_HOST", "127.0.0.1")
        .env("URLS_SELF_ISSUER", &public)
        .env("URLS_LOGIN", "http://127.0.0.1:9/login")
        .env("URLS_CONSENT", "http://127.0.0.1:9/consent")
        .env("SECRETS_SYSTEM", "konklav-tests-only-hydra-system-secret")
        .env("STRATEGIES_ACCESS_TOKEN", "jwt")
        .env("LOG_LEVEL", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(process) = spawned else {
        eprintln!("hydra isn't on the PATH (run through mise); skipping");
        return None;
    };
    let http = reqwest::Client::new();
    for _ in 0..100 {
        if http
            .get(format!("{admin}/health/ready"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            let discovery: Value = http
                .get(format!("{public}/.well-known/openid-configuration"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let issuer = discovery["issuer"].as_str().unwrap().to_owned();
            return Some(Hydra {
                process,
                public,
                admin,
                issuer,
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("hydra didn't become ready");
}

impl Hydra {
    async fn create_client(&self, client: Value) {
        let response = reqwest::Client::new()
            .post(format!("{}/admin/clients", self.admin))
            .json(&client)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{}",
            response.text().await.unwrap()
        );
    }

    async fn admin_put(&self, path: &str, body: Value) -> Value {
        let response = reqwest::Client::new()
            .put(format!("{}{path}", self.admin))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "{path}");
        response.json().await.unwrap()
    }

    fn provider(&self) -> Settings {
        Settings {
            id: "hydra".into(),
            issuer: self.issuer.clone(),
            client_id: "konklav".into(),
            client_secret: CLIENT_SECRET.into(),
            redirect_uri: CALLBACK.into(),
            scopes: vec!["openid".into(), "email".into()],
            return_urls: vec![RETURN.into()],
            provisioning: Provisioning::Create,
            ..Settings::default()
        }
    }

    /// Follows the browser from the authorization URL to Konklav's
    /// callback, accepting the login as `subject` with `id_token` claims (or
    /// rejecting it). Returns the callback URL.
    async fn authorize(&self, url: &str, subject: &str, id_token: Option<Value>) -> String {
        let browser = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let next = |response: reqwest::Response| {
            response.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .to_owned()
        };
        let login = next(browser.get(url).send().await.unwrap());
        let challenge = query(&login)["login_challenge"].clone();
        let Some(claims) = id_token else {
            let rejected = self
                .admin_put(
                    &format!(
                        "/admin/oauth2/auth/requests/login/reject?login_challenge={challenge}"
                    ),
                    json!({"error": "access_denied", "error_description": "no"}),
                )
                .await;
            return next(
                browser
                    .get(rejected["redirect_to"].as_str().unwrap())
                    .send()
                    .await
                    .unwrap(),
            );
        };
        let accepted = self
            .admin_put(
                &format!("/admin/oauth2/auth/requests/login/accept?login_challenge={challenge}"),
                json!({"subject": subject, "amr": ["pwd", "hwk"], "acr": "urn:hydra:acr:strong"}),
            )
            .await;
        let consent = next(
            browser
                .get(accepted["redirect_to"].as_str().unwrap())
                .send()
                .await
                .unwrap(),
        );
        let challenge = query(&consent)["consent_challenge"].clone();
        let accepted = self
            .admin_put(
                &format!(
                    "/admin/oauth2/auth/requests/consent/accept?consent_challenge={challenge}"
                ),
                json!({"grant_scope": ["openid", "email"], "session": {"id_token": claims}}),
            )
            .await;
        // Hydra may bounce through its own endpoint before the callback.
        let mut location = accepted["redirect_to"].as_str().unwrap().to_owned();
        while !location.starts_with(CALLBACK) {
            location = next(browser.get(&location).send().await.unwrap());
        }
        location
    }
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

/// Starts a Konklav login through Hydra and finishes it at the callback.
async fn login(
    app: &TestApp,
    hydra: &Hydra,
    subject: &str,
    claims: Option<Value>,
) -> common::Reply {
    let started = app
        .send(Method::GET, "/v1/login/oidc/hydra/start", &[], None)
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
    let state = cookie(&started, "konklav_oidc").unwrap();
    let callback = hydra.authorize(&location(&started), subject, claims).await;
    let path = callback.trim_start_matches("https://auth.example");
    app.send(Method::GET, path, &[("cookie", &state)], None)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn konklav_signs_people_in_through_hydra() {
    let Some(hydra) = hydra().await else {
        return;
    };
    hydra
        .create_client(json!({
            "client_id": "konklav",
            "client_secret": CLIENT_SECRET,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid email",
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "client_secret_basic",
        }))
        .await;
    let settings = Settings {
        methods: vec![("hwk".into(), "hwk".into())],
        grants: vec![
            konklav_server::claim_mapping::Rule::from_config(&konklav_server::config::ClaimGrant {
                claim: "groups".into(),
                equals: None,
                contains: Some("sre".into()),
                global_role: Some("operator".into()),
                tenant: None,
                roles: vec![],
            })
            .unwrap(),
        ],
        ..hydra.provider()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    for (method, path, body) in [
        (
            Method::PUT,
            "/v1/catalog",
            json!({"actions": [{"name": "env:operate"}]}),
        ),
        (
            Method::PUT,
            "/v1/tenants/root/roles/operator",
            json!({"policies": [{"action": "env:operate", "effect": "allow"}]}),
        ),
    ] {
        let reply = app.control(method, path, Some(body)).await;
        assert!(reply.status.is_success(), "{:?}", reply.body);
    }

    let done = login(
        &app,
        &hydra,
        "alice",
        Some(json!({"email": "alice@hydra.example", "email_verified": true, "groups": ["sre"]})),
    )
    .await;
    assert_eq!(
        location(&done),
        format!("{RETURN}?signed_in=true"),
        "{:?}",
        done.body
    );
    let refresh_cookie = cookie(&done, "konklav_refresh").unwrap();
    let refreshed = app
        .send(
            Method::POST,
            "/v1/refresh",
            &[
                ("cookie", &refresh_cookie),
                ("origin", ORIGIN),
                ("x-konklav-client", "web"),
            ],
            None,
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    let claims = app
        .verify(refreshed.body["access_token"].as_str().unwrap())
        .await;
    assert_eq!(claims.amr, ["fed", "hwk"], "Hydra's amr, as configured");
    let entitlements = app
        .control(
            Method::GET,
            &format!("/v1/subjects/{}/entitlements", claims.sub),
            None,
        )
        .await;
    assert_eq!(
        entitlements.body["global"],
        json!(["env:operate"]),
        "mapped from Hydra's groups"
    );
    let subject = app
        .control(Method::GET, &format!("/v1/subjects/{}", claims.sub), None)
        .await;
    let credential = &subject.body["credentials"][0];
    assert_eq!(credential["kind"], "federated");

    // A refused login at Hydra comes back as a provider error.
    let refused = login(&app, &hydra, "alice", None).await;
    assert_eq!(location(&refused), format!("{RETURN}?error=provider_error"));
}

#[tokio::test(flavor = "multi_thread")]
async fn hydra_workload_tokens_sign_in_service_principals() {
    let Some(hydra) = hydra().await else {
        return;
    };
    hydra
        .create_client(json!({
            "client_id": "ci",
            "client_secret": "ci-secret",
            "grant_types": ["client_credentials"],
            "audience": [ISSUER],
            "token_endpoint_auth_method": "client_secret_basic",
        }))
        .await;
    let token: Value = reqwest::Client::new()
        .post(format!("{}/oauth2/token", hydra.public))
        .basic_auth("ci", Some("ci-secret"))
        .form(&[("grant_type", "client_credentials"), ("audience", ISSUER)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let assertion = token["access_token"]
        .as_str()
        .expect("a JWT access token")
        .to_owned();

    let settings = Settings {
        workloads: true,
        ..hydra.provider()
    };
    let app = TestApp::with_auth(|auth| {
        auth.identity_providers = Providers::from_settings([settings]);
        auth.oidc = Some(
            OpenIdProvider::from_pem(
                include_str!("fixtures/id-token-key.pem"),
                "https://login.example/".into(),
                format!("{ISSUER}/.well-known/jwks.json"),
            )
            .unwrap(),
        );
    })
    .await;
    let deployer = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{deployer}"),
        Some(json!({"kind": "service"})),
    )
    .await;
    let created = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{deployer}/credentials"),
            // Hydra's client-credentials tokens name the client as `sub`.
            Some(json!({"kind": "federated", "provider": "hydra", "subject": "ci"})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let exchanged = app
        .send_form(
            "/v1/oauth2/token",
            &[],
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ],
        )
        .await;
    assert_eq!(exchanged.status, StatusCode::OK, "{:?}", exchanged.body);
    let claims = app
        .verify(exchanged.body["access_token"].as_str().unwrap())
        .await;
    assert_eq!(claims.sub.to_string(), deployer.to_string());
}
