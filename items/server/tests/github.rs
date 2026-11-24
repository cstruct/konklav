//! GitHub as an identity provider, against a fake GitHub: its OAuth
//! endpoints and the parts of its REST API Konklav reads.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{ORIGIN, TestApp};
use konklav_server::claim_mapping::{Condition, Grant, Rule};
use konklav_server::federation::{GitHub, Protocol, Providers, Provisioning, Settings};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CLIENT_ID: &str = "Iv1.konklav";
const CLIENT_SECRET: &str = "github secret";
const RETURN: &str = "https://app.example/signed-in";

/// What the fake GitHub says about the person behind a token.
#[derive(Clone)]
struct Account {
    user: Value,
    emails: Value,
    orgs: Value,
    teams: Value,
}

fn octocat() -> Account {
    Account {
        user: json!({
            "id": 583_231,
            "login": "octocat",
            "name": "The Octocat",
            "email": null,
            "avatar_url": "https://avatars.example/583231",
            "html_url": "https://github.example/octocat",
        }),
        emails: json!([
            {"email": "octo@old.example", "primary": false, "verified": true},
            {"email": "ada@example.com", "primary": true, "verified": true},
        ]),
        orgs: json!([{"login": "acme"}]),
        teams: json!([{"slug": "platform", "organization": {"login": "acme"}}]),
    }
}

#[derive(Default)]
struct Fake {
    /// Accounts by the code that signs them in, with its PKCE challenge.
    codes: HashMap<String, (String, Account)>,
    /// Accounts by access token.
    tokens: HashMap<String, Account>,
    /// API paths called, in order.
    calls: Vec<String>,
}

struct FakeGitHub {
    issuer: String,
    state: Arc<Mutex<Fake>>,
}

impl FakeGitHub {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(Fake::default()));
        let router = Router::new()
            .route("/login/oauth/access_token", post(token))
            .route("/api/v3/user", api("user"))
            .route("/api/v3/user/emails", api("emails"))
            .route("/api/v3/user/orgs", api("orgs"))
            .route("/api/v3/user/teams", api("teams"))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { issuer, state }
    }

    fn settings(&self) -> Settings {
        Settings {
            id: "github".into(),
            protocol: Protocol::GitHub(GitHub::new(&self.issuer).unwrap()),
            issuer: self.issuer.clone(),
            client_id: CLIENT_ID.into(),
            client_secret: CLIENT_SECRET.into(),
            redirect_uri: "https://auth.example/v1/login/oidc/github/callback".into(),
            return_urls: vec![RETURN.into()],
            provisioning: Provisioning::Create,
            ..Settings::default()
        }
    }

    /// Simulates `account` signing in at GitHub for the request at `url`.
    fn authorize(&self, url: &str, account: Account) -> String {
        let code = uuid::Uuid::now_v7().to_string();
        self.state.lock().unwrap().codes.insert(
            code.clone(),
            (query(url)["code_challenge"].clone(), account),
        );
        code
    }

    fn calls(&self) -> Vec<String> {
        std::mem::take(&mut self.state.lock().unwrap().calls)
    }
}

/// GitHub's token endpoint, which answers refusals with 200 and `error`.
async fn token(
    State(state): State<Arc<Mutex<Fake>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> axum::Json<Value> {
    assert_eq!(headers[header::ACCEPT], "application/json");
    let mut fake = state.lock().unwrap();
    let refused = json!({"error": "bad_verification_code"});
    if form.get("client_id").map(String::as_str) != Some(CLIENT_ID)
        || form.get("client_secret").map(String::as_str) != Some(CLIENT_SECRET)
    {
        return axum::Json(json!({"error": "incorrect_client_credentials"}));
    }
    let Some((challenge, account)) = fake.codes.remove(&form["code"]) else {
        return axum::Json(refused);
    };
    if URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())) != challenge {
        return axum::Json(refused);
    }
    let access_token = format!("gho_{}", uuid::Uuid::now_v7().simple());
    fake.tokens.insert(access_token.clone(), account);
    axum::Json(
        json!({"access_token": access_token, "token_type": "bearer", "scope": "read:user,user:email"}),
    )
}

/// A REST API route answering `what` about the token's account.
fn api(what: &'static str) -> axum::routing::MethodRouter<Arc<Mutex<Fake>>> {
    get(
        move |State(state): State<Arc<Mutex<Fake>>>, headers: HeaderMap| async move {
            answer(&state, &headers, what)
        },
    )
}

fn answer(
    state: &Mutex<Fake>,
    headers: &HeaderMap,
    what: &'static str,
) -> Result<axum::Json<Value>, StatusCode> {
    assert!(headers.contains_key(header::USER_AGENT), "GitHub needs one");
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let mut fake = state.lock().unwrap();
    let account = fake
        .tokens
        .get(token)
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    fake.calls.push(what.to_owned());
    Ok(axum::Json(match what {
        "user" => account.user,
        "emails" => account.emails,
        "orgs" => account.orgs,
        _ => account.teams,
    }))
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

/// Signs `account` in through GitHub, returning the authorization URL
/// Konklav sent the browser to and the reply to the callback.
async fn sign_in(app: &TestApp, github: &FakeGitHub, account: Account) -> (String, common::Reply) {
    let started = app
        .send(Method::GET, "/v1/login/oidc/github/start", &[], None)
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
    let url = location(&started);
    let state_cookie = cookie(&started, "__Host-konklav_oidc").unwrap();
    let code = github.authorize(&url, account);
    let state = query(&url)["state"].clone();
    let reply = app
        .send(
            Method::GET,
            &format!("/v1/login/oidc/github/callback?state={state}&code={code}"),
            &[("cookie", &state_cookie)],
            None,
        )
        .await;
    (url, reply)
}

/// The subject a successful sign-in signed in.
async fn subject_of(app: &TestApp, reply: &common::Reply) -> String {
    assert_eq!(location(reply), format!("{RETURN}?signed_in=true"));
    let refresh = cookie(reply, "__Host-konklav_refresh").unwrap();
    let refreshed = app
        .send(
            Method::POST,
            "/v1/refresh",
            &[
                ("cookie", &refresh),
                ("origin", ORIGIN),
                ("x-konklav-client", "web"),
            ],
            None,
        )
        .await;
    app.verify(refreshed.body["access_token"].as_str().unwrap())
        .await
        .sub
        .to_string()
}

// r[verify federation.github]
// r[verify federation.github.identity]
#[tokio::test(flavor = "multi_thread")]
async fn github_accounts_sign_in_by_their_numeric_id() {
    let github = FakeGitHub::start().await;
    let app = TestApp::with_identity_providers(Providers::from_settings([github.settings()])).await;

    let (url, first) = sign_in(&app, &github, octocat()).await;
    assert!(
        url.starts_with(&format!("{}/login/oauth/authorize?", github.issuer)),
        "{url}"
    );
    let params = query(&url);
    assert_eq!(params["client_id"], CLIENT_ID);
    assert_eq!(params["scope"], "read:user user:email");
    assert_eq!(params["code_challenge_method"], "S256");
    assert!(!params.contains_key("nonce"), "GitHub has no ID token");
    let subject = subject_of(&app, &first).await;
    assert_eq!(
        github.calls(),
        ["user", "emails"],
        "no groups without read:org"
    );

    // A renamed account with another address is still the same one.
    let mut renamed = octocat();
    renamed.user["login"] = json!("octo-renamed");
    renamed.emails = json!([{"email": "new@example.net", "primary": true, "verified": true}]);
    let (_, again) = sign_in(&app, &github, renamed).await;
    assert_eq!(subject_of(&app, &again).await, subject);

    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    let credential = &detail.body["credentials"][0];
    assert_eq!(credential["kind"], "federated");
    assert!(
        credential.to_string().contains("583231"),
        "keyed by the id: {credential}"
    );
}

// r[verify federation.github.identity]
#[tokio::test(flavor = "multi_thread")]
async fn only_verified_github_emails_link_accounts() {
    let github = FakeGitHub::start().await;
    let settings = Settings {
        provisioning: Provisioning::Link,
        link_verified_email_domains: vec!["example.com".into()],
        ..github.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let ada = app.human("ada@example.com", "correct horse battery").await;

    let mut unverified = octocat();
    unverified.emails = json!([{"email": "ada@example.com", "primary": true, "verified": false}]);
    let (_, refused) = sign_in(&app, &github, unverified).await;
    assert_eq!(
        location(&refused),
        format!("{RETURN}?error=account_not_linked")
    );

    let (_, linked) = sign_in(&app, &github, octocat()).await;
    assert_eq!(subject_of(&app, &linked).await, ada);
}

// r[verify federation.github.groups]
#[tokio::test(flavor = "multi_thread")]
async fn github_teams_drive_claim_mapping_with_read_org() {
    let github = FakeGitHub::start().await;
    let tenant = uuid::Uuid::now_v7();
    let settings = Settings {
        scopes: vec!["read:user".into(), "user:email".into(), "read:org".into()],
        grants: vec![Rule {
            claim: "groups".into(),
            condition: Condition::Contains("acme/platform".into()),
            grant: Grant::Tenant {
                tenant: konklav_store::tenants::Reference::Id(tenant.into()),
                roles: vec![],
            },
        }],
        ..github.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let created = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({})),
        )
        .await;
    assert!(created.status.is_success(), "{:?}", created.body);

    let (_, reply) = sign_in(&app, &github, octocat()).await;
    let subject = subject_of(&app, &reply).await;
    assert_eq!(github.calls(), ["user", "emails", "orgs", "teams"]);
    let memberships = app
        .control(
            Method::GET,
            &format!("/v1/tenants/{tenant}/memberships"),
            None,
        )
        .await;
    assert_eq!(
        memberships.body[0]["subject_id"], subject,
        "{:?}",
        memberships.body
    );
}

// r[verify federation.github]
#[tokio::test(flavor = "multi_thread")]
async fn refused_github_exchanges_fail_the_login() {
    let github = FakeGitHub::start().await;
    let settings = Settings {
        client_secret: "wrong".into(),
        ..github.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let (_, reply) = sign_in(&app, &github, octocat()).await;
    assert_eq!(location(&reply), format!("{RETURN}?error=provider_error"));
    assert_eq!(github.calls(), Vec::<String>::new());
}
