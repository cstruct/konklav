#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{ORIGIN, TestApp};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use konklav_server::federation::{Providers, Provisioning, Settings};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROVIDER_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUoptOOQL2DZqHV4Q
GpDMUYd6rsbhOjYqdxTU6xh4DmahRANCAARjr/UQTOoK84SKa5ZB1Rg9mLRWjzyy
p1XNGpwF1zXMHj8NrRZRBsdiy2jZvNVSLlPqzmK3P4YLDAtSoKNCeXst
-----END PRIVATE KEY-----";
const PROVIDER_X: &str = "Y6_1EEzqCvOEimuWQdUYPZi0Vo88sqdVzRqcBdc1zB4";
const PROVIDER_Y: &str = "Pw2tFlEGx2LLaNm81VIuU-rOYrc_hgsMC1Kgo0J5ey0";
const CLIENT_ID: &str = "konklav-test";
const CLIENT_SECRET: &str = "client secret";
const RETURN: &str = "https://app.example/signed-in";
const UPSTREAM_SUB: &str = "Upstream-Ada";

/// An authorization the fake provider will exchange a code for.
#[derive(Clone)]
struct Grant {
    code_challenge: String,
    /// Claims of the ID token; `iss`, `aud`, `exp` and `iat` are filled in
    /// unless present.
    claims: Value,
    /// How to sign the ID token.
    signing: Signing,
    /// userinfo for the access token, which is only issued with it.
    userinfo: Option<Value>,
}

#[derive(Clone, Copy)]
enum Signing {
    Provider,
    UnknownKey,
    Symmetric,
}

#[derive(Default)]
struct Fake {
    issuer: String,
    grants: HashMap<String, Grant>,
    /// userinfo by access token.
    userinfo: HashMap<String, Value>,
    jwks_fetches: usize,
}

/// A minimal OpenID provider: discovery, keys, the token endpoint and
/// userinfo.
/// Authorization is simulated by registering grants directly.
struct FakeProvider {
    issuer: String,
    state: Arc<Mutex<Fake>>,
}

impl FakeProvider {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(Fake {
            issuer: issuer.clone(),
            ..Fake::default()
        }));
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .route("/userinfo", get(userinfo))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { issuer, state }
    }

    fn settings(&self) -> Settings {
        Settings {
            id: "ops".into(),
            issuer: self.issuer.clone(),
            client_id: CLIENT_ID.into(),
            client_secret: CLIENT_SECRET.into(),
            redirect_uri: "https://auth.example/v1/login/oidc/ops/callback".into(),
            scopes: vec![],
            return_urls: vec![RETURN.into()],
            methods: vec![("hwk".into(), "hwk".into())],
            require_acr: None,
            max_age: None,
            ..Settings::default()
        }
    }

    /// Simulates the subject signing in at the provider for the
    /// authorization request at `url`, returning the code.
    fn authorize(&self, url: &str, claims: Value, signing: Signing) -> String {
        self.authorize_with(url, claims, signing, None)
    }

    /// Like `authorize`, but the token response also carries an access
    /// token that userinfo answers with `userinfo`.
    fn authorize_with(
        &self,
        url: &str,
        claims: Value,
        signing: Signing,
        userinfo: Option<Value>,
    ) -> String {
        let params = query(url);
        let mut claims = claims;
        if claims.get("nonce").is_none() {
            claims["nonce"] = json!(params["nonce"]);
        }
        let code = uuid::Uuid::now_v7().to_string();
        self.state.lock().unwrap().grants.insert(
            code.clone(),
            Grant {
                code_challenge: params["code_challenge"].clone(),
                claims,
                signing,
                userinfo,
            },
        );
        code
    }
}

async fn discovery(State(state): State<Arc<Mutex<Fake>>>) -> axum::Json<Value> {
    let issuer = state.lock().unwrap().issuer.clone();
    axum::Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
    }))
}

async fn userinfo(
    State(state): State<Arc<Mutex<Fake>>>,
    headers: HeaderMap,
) -> Result<axum::Json<Value>, StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let info = state.lock().unwrap().userinfo.get(token).cloned();
    info.map(axum::Json).ok_or(StatusCode::UNAUTHORIZED)
}

async fn jwks(State(state): State<Arc<Mutex<Fake>>>) -> axum::Json<Value> {
    state.lock().unwrap().jwks_fetches += 1;
    axum::Json(json!({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
        "x": PROVIDER_X, "y": PROVIDER_Y,
    }]}))
}

async fn token(
    State(state): State<Arc<Mutex<Fake>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<axum::Json<Value>, StatusCode> {
    let expected = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(&expected)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (issuer, grant, access_token) = {
        let mut fake = state.lock().unwrap();
        let grant = fake
            .grants
            .remove(&form["code"])
            .ok_or(StatusCode::BAD_REQUEST)?;
        let access_token = grant.userinfo.clone().map(|info| {
            let token = uuid::Uuid::now_v7().to_string();
            fake.userinfo.insert(token.clone(), info);
            token
        });
        (fake.issuer.clone(), grant, access_token)
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes()));
    if challenge != grant.code_challenge {
        return Err(StatusCode::BAD_REQUEST);
    }
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({"iss": issuer, "aud": CLIENT_ID, "iat": now, "exp": now + 300});
    for (key, value) in grant.claims.as_object().unwrap() {
        claims[key] = value.clone();
    }
    let id_token = match grant.signing {
        Signing::Provider | Signing::UnknownKey => {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some(match grant.signing {
                Signing::Provider => "k1".into(),
                _ => "missing".into(),
            });
            let key = EncodingKey::from_ec_pem(PROVIDER_KEY.as_bytes()).unwrap();
            jsonwebtoken::encode(&header, &claims, &key).unwrap()
        }
        Signing::Symmetric => {
            let mut header = Header::new(Algorithm::HS256);
            header.kid = Some("k1".into());
            jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(b"shared")).unwrap()
        }
    };
    let mut body = json!({"id_token": id_token, "token_type": "Bearer"});
    if let Some(token) = access_token {
        body["access_token"] = json!(token);
    }
    Ok(axum::Json(body))
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

/// The `name=value` part of a Set-Cookie header for `name`.
fn cookie(reply: &common::Reply, name: &str) -> Option<String> {
    reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
}

/// Starts a federated login, returning the provider URL and the browser's
/// state cookie.
async fn start(app: &TestApp) -> (String, String) {
    let reply = app
        .send(Method::GET, "/v1/login/oidc/ops/start", &[], None)
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{:?}", reply.body);
    (
        location(&reply),
        cookie(&reply, "__Host-konklav_oidc").unwrap(),
    )
}

async fn callback(
    app: &TestApp,
    url: &str,
    code: &str,
    state_cookie: Option<&str>,
) -> common::Reply {
    let state = query(url)["state"].clone();
    let uri = format!("/v1/login/oidc/ops/callback?state={state}&code={code}");
    let headers: Vec<(&str, &str)> = state_cookie.map(|c| ("cookie", c)).into_iter().collect();
    app.send(Method::GET, &uri, &headers, None).await
}

/// Links the provider account `sub` to the subject signed in with `token`.
async fn link(app: &TestApp, provider: &FakeProvider, token: &str, claims: Value) -> common::Reply {
    let auth = format!("Bearer {token}");
    let started = app
        .send(
            Method::POST,
            "/v1/credentials/oidc/ops/link",
            &[
                ("authorization", &auth),
                ("origin", ORIGIN),
                ("x-konklav-client", "web"),
            ],
            Some(json!({})),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let url = started.body["authorization_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let code = provider.authorize(&url, claims, Signing::Provider);
    let state_cookie = cookie(&started, "__Host-konklav_oidc").unwrap();
    callback(app, &url, &code, Some(&state_cookie)).await
}

async fn signed_in(app: &TestApp) -> String {
    let subject = app.human("ada@example.com", "correct horse battery").await;
    let login = app.login("ada@example.com", "correct horse battery").await;
    let _ = subject;
    login.body["access_token"].as_str().unwrap().to_owned()
}

// r[verify federation.idp.code-flow]
// r[verify federation.linking]
// r[verify federation.session]
// r[verify federation.methods]
#[tokio::test(flavor = "multi_thread")]
async fn linked_provider_accounts_sign_in_with_a_browser_session() {
    let provider = FakeProvider::start().await;
    let app =
        TestApp::with_identity_providers(Providers::from_settings([provider.settings()])).await;
    let token = signed_in(&app).await;
    let subject = app.verify(&token).await.sub;

    let linked = link(&app, &provider, &token, json!({"sub": UPSTREAM_SUB})).await;
    assert_eq!(linked.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&linked), format!("{RETURN}?linked=true"));
    assert!(
        cookie(&linked, "__Host-konklav_oidc").is_some_and(|c| c == "__Host-konklav_oidc="),
        "the state cookie is cleared"
    );

    let (url, state_cookie) = start(&app).await;
    let params = query(&url);
    assert!(url.starts_with(&format!("{}/authorize?", provider.issuer)));
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["client_id"], CLIENT_ID);
    let code = provider.authorize(
        &url,
        json!({"sub": UPSTREAM_SUB, "amr": ["hwk", "face"]}),
        Signing::Provider,
    );
    let done = callback(&app, &url, &code, Some(&state_cookie)).await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{:?}", done.body);
    assert_eq!(location(&done), format!("{RETURN}?signed_in=true"));
    let refresh_cookie = cookie(&done, "__Host-konklav_refresh").expect("a refresh cookie");

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
    assert_eq!(claims.sub, subject);
    assert_eq!(
        claims.amr,
        ["fed", "hwk"],
        "unmapped methods aren't credited"
    );

    // Replaying the same state fails, as does a callback from another browser.
    let replayed = callback(&app, &url, &code, Some(&state_cookie)).await;
    assert_eq!(replayed.status, StatusCode::BAD_REQUEST);
    let (url, _) = start(&app).await;
    let code = provider.authorize(&url, json!({"sub": UPSTREAM_SUB}), Signing::Provider);
    assert_eq!(
        callback(&app, &url, &code, None).await.status,
        StatusCode::BAD_REQUEST
    );
}

// r[verify federation.idp.id-token]
// r[verify federation.provisioning]
#[tokio::test(flavor = "multi_thread")]
async fn invalid_id_tokens_and_unlinked_accounts_are_refused() {
    let provider = FakeProvider::start().await;
    let app =
        TestApp::with_identity_providers(Providers::from_settings([provider.settings()])).await;
    let token = signed_in(&app).await;
    link(&app, &provider, &token, json!({"sub": UPSTREAM_SUB})).await;

    for (claims, signing, error) in [
        (
            json!({"sub": "nobody"}),
            Signing::Provider,
            "account_not_linked",
        ),
        (
            json!({"sub": UPSTREAM_SUB, "nonce": "other"}),
            Signing::Provider,
            "invalid_id_token",
        ),
        (
            json!({"sub": UPSTREAM_SUB, "aud": "someone-else"}),
            Signing::Provider,
            "invalid_id_token",
        ),
        (
            json!({"sub": UPSTREAM_SUB, "iss": "https://evil.example"}),
            Signing::Provider,
            "invalid_id_token",
        ),
        (
            json!({"sub": UPSTREAM_SUB, "aud": [CLIENT_ID, "other"], "azp": "other"}),
            Signing::Provider,
            "invalid_id_token",
        ),
        (
            json!({"sub": UPSTREAM_SUB, "exp": 1}),
            Signing::Provider,
            "invalid_id_token",
        ),
        (
            json!({"sub": UPSTREAM_SUB}),
            Signing::UnknownKey,
            "invalid_id_token",
        ),
        (
            json!({"sub": UPSTREAM_SUB}),
            Signing::Symmetric,
            "invalid_id_token",
        ),
    ] {
        let (url, state_cookie) = start(&app).await;
        let code = provider.authorize(&url, claims.clone(), signing);
        let reply = callback(&app, &url, &code, Some(&state_cookie)).await;
        assert_eq!(
            location(&reply),
            format!("{RETURN}?error={error}"),
            "{claims}"
        );
        assert!(cookie(&reply, "__Host-konklav_refresh").is_none());
    }

    // An account linked to one subject can't be linked to another.
    app.human("bo@example.com", "correct horse battery").await;
    let other = app.login("bo@example.com", "correct horse battery").await;
    let reply = link(
        &app,
        &provider,
        other.body["access_token"].as_str().unwrap(),
        json!({"sub": UPSTREAM_SUB}),
    )
    .await;
    assert_eq!(
        location(&reply),
        format!("{RETURN}?error=account_linked_elsewhere")
    );
}

// r[verify federation.session-lifetime]
#[tokio::test(flavor = "multi_thread")]
async fn providers_enforce_their_requirements_and_cap_sessions() {
    let provider = FakeProvider::start().await;
    let settings = Settings {
        require_acr: Some("urn:hwk".into()),
        session_lifetime: Some(chrono::Duration::seconds(600)),
        ..provider.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let token = signed_in(&app).await;
    link(
        &app,
        &provider,
        &token,
        json!({"sub": UPSTREAM_SUB, "acr": "urn:hwk"}),
    )
    .await;

    let (url, state_cookie) = start(&app).await;
    assert_eq!(query(&url)["acr_values"], "urn:hwk");
    let code = provider.authorize(
        &url,
        json!({"sub": UPSTREAM_SUB, "acr": "urn:pwd"}),
        Signing::Provider,
    );
    let reply = callback(&app, &url, &code, Some(&state_cookie)).await;
    assert_eq!(
        location(&reply),
        format!("{RETURN}?error=requirements_not_met")
    );

    let (url, state_cookie) = start(&app).await;
    let code = provider.authorize(
        &url,
        json!({"sub": UPSTREAM_SUB, "acr": "urn:hwk"}),
        Signing::Provider,
    );
    let reply = callback(&app, &url, &code, Some(&state_cookie)).await;
    let refresh = reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-konklav_refresh="))
        .expect("a refresh cookie");
    let max_age: i64 = refresh
        .split(';')
        .find_map(|part| part.trim().strip_prefix("Max-Age="))
        .unwrap()
        .parse()
        .unwrap();
    assert!((590..=600).contains(&max_age), "Max-Age={max_age}");
}

#[tokio::test(flavor = "multi_thread")]
async fn return_urls_must_be_registered() {
    let provider = FakeProvider::start().await;
    let app =
        TestApp::with_identity_providers(Providers::from_settings([provider.settings()])).await;
    let reply = app
        .send(
            Method::GET,
            "/v1/login/oidc/ops/start?return_to=https://evil.example/",
            &[],
            None,
        )
        .await;
    assert_eq!(reply.code(), "INVALID_REQUEST");
    let unknown = app
        .send(Method::GET, "/v1/login/oidc/nope/start", &[], None)
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
}

/// Signs in at the provider with `claims` and returns the reply to the
/// callback.
async fn federated_login(app: &TestApp, provider: &FakeProvider, claims: Value) -> common::Reply {
    let (url, state_cookie) = start(app).await;
    let code = provider.authorize(&url, claims, Signing::Provider);
    callback(app, &url, &code, Some(&state_cookie)).await
}

/// The subject a successful federated login signed in.
async fn signed_in_subject(app: &TestApp, reply: &common::Reply) -> String {
    assert_eq!(location(reply), format!("{RETURN}?signed_in=true"));
    let refresh_cookie = cookie(reply, "__Host-konklav_refresh").unwrap();
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
    app.verify(refreshed.body["access_token"].as_str().unwrap())
        .await
        .sub
        .to_string()
}

// r[verify federation.provisioning]
#[tokio::test(flavor = "multi_thread")]
async fn creating_providers_provision_subjects_for_unknown_accounts() {
    let provider = FakeProvider::start().await;
    let settings = Settings {
        provisioning: Provisioning::Create,
        ..provider.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let first = federated_login(&app, &provider, json!({"sub": "new-person"})).await;
    let subject = signed_in_subject(&app, &first).await;
    let again = federated_login(&app, &provider, json!({"sub": "new-person"})).await;
    assert_eq!(
        signed_in_subject(&app, &again).await,
        subject,
        "the account stays linked"
    );
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    assert_eq!(detail.body["kind"], "human");
    assert_eq!(detail.body["credentials"][0]["kind"], "federated");
}

// r[verify federation.linking]
#[tokio::test(flavor = "multi_thread")]
async fn verified_emails_link_only_in_allowed_domains() {
    let provider = FakeProvider::start().await;
    let settings = Settings {
        link_verified_email_domains: vec!["example.com".into()],
        ..provider.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let ada = app.human("ada@example.com", "correct horse battery").await;
    app.human("bo@other.example", "correct horse battery").await;

    for claims in [
        json!({"sub": "u1", "email": "ada@example.com", "email_verified": false}),
        json!({"sub": "u2", "email": "ada@example.com"}),
        json!({"sub": "u3", "email": "bo@other.example", "email_verified": true}),
        json!({"sub": "u4", "email": "nobody@example.com", "email_verified": true}),
    ] {
        let reply = federated_login(&app, &provider, claims.clone()).await;
        assert_eq!(
            location(&reply),
            format!("{RETURN}?error=account_not_linked"),
            "{claims}"
        );
    }
    let reply = federated_login(
        &app,
        &provider,
        json!({"sub": "u5", "email": "Ada@Example.com", "email_verified": true}),
    )
    .await;
    assert_eq!(signed_in_subject(&app, &reply).await, ada);
}

// r[verify federation.idp.userinfo]
#[tokio::test(flavor = "multi_thread")]
async fn userinfo_claims_count_alongside_the_id_tokens() {
    let provider = FakeProvider::start().await;
    let settings = Settings {
        link_verified_email_domains: vec!["example.com".into()],
        ..provider.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let ada = app.human("ada@example.com", "correct horse battery").await;
    let login = |claims: Value, userinfo: Value| {
        let (app, provider) = (&app, &provider);
        async move {
            let (url, state_cookie) = start(app).await;
            let code = provider.authorize_with(&url, claims, Signing::Provider, Some(userinfo));
            callback(app, &url, &code, Some(&state_cookie)).await
        }
    };

    // The ID token's claims win: its unverified address doesn't link.
    let reply = login(
        json!({"sub": "u1", "email": "ada@example.com", "email_verified": false}),
        json!({"sub": "u1", "email": "ada@example.com", "email_verified": true}),
    )
    .await;
    assert_eq!(
        location(&reply),
        format!("{RETURN}?error=account_not_linked")
    );

    // userinfo for another subject is refused.
    let reply = login(
        json!({"sub": "u2"}),
        json!({"sub": "someone-else", "email": "ada@example.com", "email_verified": true}),
    )
    .await;
    assert_eq!(location(&reply), format!("{RETURN}?error=provider_error"));

    // A verified address only in userinfo links.
    let reply = login(
        json!({"sub": "u3"}),
        json!({"sub": "u3", "email": "ada@example.com", "email_verified": true}),
    )
    .await;
    assert_eq!(signed_in_subject(&app, &reply).await, ada);
}

// r[verify federation.mapping.rules]
// r[verify federation.mapping.managed]
#[tokio::test(flavor = "multi_thread")]
async fn claim_mapping_manages_only_its_own_grants() {
    let provider = FakeProvider::start().await;
    let tenant = uuid::Uuid::now_v7();
    let rule = |claim: &str,
                contains: &str,
                global_role: Option<&str>,
                tenant: Option<String>,
                roles: &[&str]| {
        konklav_server::claim_mapping::Rule::from_config(&konklav_server::config::ClaimGrant {
            claim: claim.into(),
            equals: None,
            contains: Some(contains.into()),
            global_role: global_role.map(Into::into),
            tenant,
            roles: roles.iter().map(|r| (*r).into()).collect(),
        })
        .unwrap()
    };
    let settings = Settings {
        provisioning: Provisioning::Create,
        grants: vec![
            rule("groups", "sre", Some("operator"), None, &[]),
            rule(
                "groups",
                "support",
                None,
                Some(tenant.to_string()),
                &["agent"],
            ),
        ],
        ..provider.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    for (method, path, body) in [
        (
            Method::PUT,
            "/v1/catalog".to_owned(),
            json!({"actions": [{"name": "ops:run"}, {"name": "tickets:read"}, {"name": "local:thing"}]}),
        ),
        (
            Method::PUT,
            "/v1/tenants/root/roles/operator".to_owned(),
            json!({"policies": [{"action": "ops:run", "effect": "allow"}]}),
        ),
        (
            Method::PUT,
            "/v1/tenants/root/roles/local".to_owned(),
            json!({"policies": [{"action": "local:thing", "effect": "allow"}]}),
        ),
        (Method::PUT, format!("/v1/tenants/{tenant}"), json!({})),
        (
            Method::PUT,
            format!("/v1/tenants/{tenant}/roles/agent"),
            json!({"policies": [{"action": "tickets:read", "effect": "allow"}]}),
        ),
    ] {
        let reply = app.control(method, &path, Some(body)).await;
        assert!(reply.status.is_success(), "{path}: {:?}", reply.body);
    }

    let reply = federated_login(
        &app,
        &provider,
        json!({"sub": "op", "groups": ["sre", "support"]}),
    )
    .await;
    let subject = signed_in_subject(&app, &reply).await;
    // A grant made outside claim mapping.
    let local = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": "local"})),
        )
        .await;
    assert!(local.status.is_success(), "{:?}", local.body);
    let entitlements = |tenant: Option<uuid::Uuid>| {
        let app = &app;
        let subject = subject.clone();
        async move {
            let query = tenant.map(|t| format!("?tenant={t}")).unwrap_or_default();
            app.control(
                Method::GET,
                &format!("/v1/subjects/{subject}/entitlements{query}"),
                None,
            )
            .await
            .body
        }
    };
    let granted = entitlements(Some(tenant)).await;
    assert_eq!(granted["global"], json!(["local:thing", "ops:run"]));
    assert_eq!(granted["tenant"], json!(["tickets:read"]));

    // Leaving both groups removes the managed grants and ends the managed
    // membership, but keeps the local grant.
    let reply = federated_login(&app, &provider, json!({"sub": "op", "groups": []})).await;
    signed_in_subject(&app, &reply).await;
    let granted = entitlements(Some(tenant)).await;
    assert_eq!(granted["global"], json!(["local:thing"]));
    assert_eq!(granted["tenant"], json!([]));
    let memberships = app
        .control(
            Method::GET,
            &format!("/v1/tenants/{tenant}/memberships"),
            None,
        )
        .await;
    assert!(
        memberships
            .body
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["state"] == "ended"),
        "{:?}",
        memberships.body
    );

    // Rejoining re-grants.
    let reply = federated_login(&app, &provider, json!({"sub": "op", "groups": ["support"]})).await;
    signed_in_subject(&app, &reply).await;
    assert_eq!(
        entitlements(Some(tenant)).await["tenant"],
        json!(["tickets:read"])
    );
}

// r[verify federation.jwks-refresh]
#[tokio::test(flavor = "multi_thread")]
async fn unknown_key_ids_cannot_force_key_fetches() {
    let provider = FakeProvider::start().await;
    let upstream =
        konklav_server::federation::Provider::new(provider.settings(), reqwest::Client::new());
    let key = EncodingKey::from_ec_pem(PROVIDER_KEY.as_bytes()).unwrap();
    let now = chrono::Utc::now().timestamp();
    for n in 0..10 {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(format!("unknown-{n}"));
        let token = jsonwebtoken::encode(
            &header,
            &json!({"iss": provider.issuer, "sub": "w", "aud": "a", "exp": now + 60}),
            &key,
        )
        .unwrap();
        assert!(
            upstream
                .verify_assertion(&token, &["a".into()])
                .await
                .is_err()
        );
    }
    assert_eq!(
        provider.state.lock().unwrap().jwks_fetches,
        1,
        "the first fetch is recent, so unknown keys don't refetch"
    );
}

// r[verify federation.local-mfa]
#[tokio::test(flavor = "multi_thread")]
async fn providers_can_require_local_mfa() {
    let provider = FakeProvider::start().await;
    let settings = Settings {
        provisioning: Provisioning::Create,
        local_mfa_factors: 1,
        ..provider.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let reply = federated_login(&app, &provider, json!({"sub": "new-person"})).await;
    assert_eq!(location(&reply), format!("{RETURN}?signed_in=mfa_required"));
    assert!(
        cookie(&reply, "__Host-konklav_refresh").is_none(),
        "no refresh token before MFA"
    );
    let partial = cookie(&reply, "__Host-konklav_partial").unwrap();
    let take = |cookie: Option<String>| {
        let app = &app;
        async move {
            let mut headers = vec![("origin", ORIGIN), ("x-konklav-client", "web")];
            let cookie = cookie.unwrap_or_default();
            if !cookie.is_empty() {
                headers.push(("cookie", cookie.as_str()));
            }
            app.send(Method::POST, "/v1/login/oidc/partial", &headers, None)
                .await
        }
    };
    let taken = take(Some(partial.clone())).await;
    assert_eq!(taken.body["token_kind"], "partial", "{:?}", taken.body);
    assert!(
        taken
            .set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-konklav_partial=;")),
        "the cookie is cleared once taken"
    );
    assert_eq!(take(None).await.code(), "UNAUTHENTICATED");
}

// r[verify federation.pass-claims]
#[tokio::test(flavor = "multi_thread")]
async fn configured_claims_are_kept_on_the_federated_session() {
    let provider = FakeProvider::start().await;
    let settings = Settings {
        provisioning: Provisioning::Create,
        pass_claims: [(
            "profile".to_owned(),
            vec!["name".to_owned(), "locale".to_owned()],
        )]
        .into(),
        ..provider.settings()
    };
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    let reply = federated_login(
        &app,
        &provider,
        json!({"sub": "passing", "name": "Ada Lovelace", "department": "engines"}),
    )
    .await;
    signed_in_subject(&app, &reply).await;
    let mut conn = app.db.pool().get().await.unwrap();
    let sessions = konklav_store::sessions::list(
        &mut conn,
        &konklav_store::sessions::SessionFilter::default(),
        None,
        None,
        100,
    )
    .await
    .unwrap();
    let passed: Vec<_> = sessions
        .iter()
        .filter_map(|s| s.identity_claims.clone())
        .collect();
    assert_eq!(
        passed,
        [json!({"profile": {"name": "Ada Lovelace"}})],
        "only configured claims the provider reported"
    );
}
