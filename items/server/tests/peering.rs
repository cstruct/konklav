#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::{Method, StatusCode, header};
use common::{ISSUER, ORIGIN, TestApp};
use conclave_server::federation::{Providers, Provisioning, Settings};
use conclave_server::oidc::OpenIdProvider;
use serde_json::{Value, json};

const ID_TOKEN_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUoptOOQL2DZqHV4Q
GpDMUYd6rsbhOjYqdxTU6xh4DmahRANCAARjr/UQTOoK84SKa5ZB1Rg9mLRWjzyy
p1XNGpwF1zXMHj8NrRZRBsdiy2jZvNVSLlPqzmK3P4YLDAtSoKNCeXst
-----END PRIVATE KEY-----";
const PASSWORD: &str = "correct horse battery";
const DOWN_CALLBACK: &str = "https://down.example/v1/login/oidc/ops/callback";
const DOWN_RETURN: &str = "https://console.down.example/";

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

async fn control_ok(app: &TestApp, method: Method, path: &str, body: Option<Value>) -> Value {
    let reply = app.control(method, path, body).await;
    assert!(reply.status.is_success(), "{path}: {:?}", reply.body);
    reply.body
}

/// An operators' instance (served over TCP) and an environment that
/// federates to it.
struct Federation {
    upstream: TestApp,
    upstream_base: String,
    client_secret: String,
    /// The operator, at the upstream.
    operator: String,
    operator_token: String,
}

async fn upstream() -> Federation {
    let (upstream, base) = TestApp::serving(|auth, base| {
        auth.oidc = Some(
            OpenIdProvider::from_pem(
                ID_TOKEN_KEY,
                "https://login.ops.example/".into(),
                format!("{base}/.well-known/jwks.json"),
            )
            .unwrap(),
        );
    })
    .await;
    let operator = upstream.human("ada@ops.example", PASSWORD).await;
    control_ok(
        &upstream,
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "ops:run"}]})),
    )
    .await;
    control_ok(
        &upstream,
        Method::PUT,
        "/v1/tenants/root/roles/sre",
        Some(json!({})),
    )
    .await;
    control_ok(
        &upstream,
        Method::POST,
        &format!("/v1/subjects/{operator}/global-assignments"),
        Some(json!({"role": "sre"})),
    )
    .await;
    control_ok(
        &upstream,
        Method::PUT,
        "/v1/oidc/clients/down",
        Some(json!({
            "kind": "confidential",
            "redirect_uris": [DOWN_CALLBACK],
            "scopes": ["openid", "groups"],
            "audience": "down",
            "visible_groups": ["sre"],
        })),
    )
    .await;
    let client_secret = control_ok(
        &upstream,
        Method::POST,
        "/v1/oidc/clients/down/secret",
        None,
    )
    .await["client_secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let operator_token = upstream.login("ada@ops.example", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    Federation {
        upstream,
        upstream_base: base,
        client_secret,
        operator,
        operator_token,
    }
}

impl Federation {
    fn provider(&self) -> Settings {
        Settings {
            id: "ops".into(),
            issuer: self.upstream_base.clone(),
            client_id: "down".into(),
            client_secret: self.client_secret.clone(),
            redirect_uri: DOWN_CALLBACK.into(),
            scopes: vec!["openid".into(), "groups".into()],
            return_urls: vec![DOWN_RETURN.into()],
            provisioning: Provisioning::Create,
            grants: vec![
                conclave_server::claim_mapping::Rule::from_config(
                    &conclave_server::config::ClaimGrant {
                        claim: "groups".into(),
                        equals: None,
                        contains: Some("sre".into()),
                        global_role: Some("operator".into()),
                        tenant: None,
                        roles: vec![],
                    },
                )
                .unwrap(),
            ],
            peering: true,
            ..Settings::default()
        }
    }

    /// The operator signs in to `downstream` through the upstream, with real
    /// HTTP between the instances. Returns the downstream callback's reply.
    async fn sign_in(&self, downstream: &TestApp) -> common::Reply {
        let started = downstream
            .send(Method::GET, "/v1/login/oidc/ops/start", &[], None)
            .await;
        assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
        let state_cookie = cookie(&started, "conclave_oidc").unwrap();
        let authorize = location(&started);
        let path = authorize.trim_start_matches(&self.upstream_base);

        let up = &self.upstream;
        let handed_off = up.send(Method::GET, path, &[], None).await;
        assert_eq!(
            handed_off.status,
            StatusCode::SEE_OTHER,
            "{:?}",
            handed_off.body
        );
        let request = query(&location(&handed_off))["login_request"].clone();
        let browser = cookie(&handed_off, "conclave_authorize").unwrap();
        let auth = format!("Bearer {}", self.operator_token);
        let accepted = up
            .send(
                Method::POST,
                &format!("/v1/oauth2/login-requests/{request}/accept"),
                &[
                    ("authorization", &auth),
                    ("origin", ORIGIN),
                    ("x-conclave-client", "web"),
                ],
                None,
            )
            .await;
        assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
        let resume = accepted.body["redirect_to"].as_str().unwrap();
        let resumed = up
            .send(
                Method::GET,
                resume.trim_start_matches(&self.upstream_base),
                &[("cookie", &browser)],
                None,
            )
            .await;
        let back = location(&resumed);
        assert!(back.starts_with(DOWN_CALLBACK), "{back}");
        let callback = back.trim_start_matches("https://down.example");
        downstream
            .send(Method::GET, callback, &[("cookie", &state_cookie)], None)
            .await
    }
}

async fn refresh(app: &TestApp, reply: &common::Reply) -> common::Reply {
    let refresh_cookie = cookie(reply, "conclave_refresh").expect("a refresh cookie");
    app.send(
        Method::POST,
        "/v1/refresh",
        &[
            ("cookie", &refresh_cookie),
            ("origin", ORIGIN),
            ("x-conclave-client", "web"),
        ],
        None,
    )
    .await
}

async fn downstream(settings: Settings) -> TestApp {
    let app = TestApp::with_identity_providers(Providers::from_settings([settings])).await;
    control_ok(
        &app,
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "env:operate"}]})),
    )
    .await;
    control_ok(
        &app,
        Method::PUT,
        "/v1/tenants/root/roles/operator",
        Some(json!({"policies": [{"action": "env:operate", "effect": "allow"}]})),
    )
    .await;
    app
}

// r[verify federation.peer.feed]
// r[verify federation.peer.standard]
#[tokio::test(flavor = "multi_thread")]
async fn downstreams_follow_the_upstream_feed() {
    let federation = upstream().await;
    let settings = federation.provider();
    let down = downstream(settings).await;
    let signed_in = federation.sign_in(&down).await;
    assert_eq!(
        location(&signed_in),
        format!("{DOWN_RETURN}?signed_in=true")
    );
    let refreshed = refresh(&down, &signed_in).await;
    let local = down
        .verify(refreshed.body["access_token"].as_str().unwrap())
        .await
        .sub;
    assert_eq!(
        global_entitlements(&down, &local.to_string()).await,
        json!(["env:operate"])
    );

    // Leaving the group upstream removes the grant downstream, without a
    // new login.
    let provider = down
        .state
        .auth
        .identity_providers
        .get("ops")
        .unwrap()
        .clone();
    conclave_server::peering::sync(&down.state, &provider)
        .await
        .unwrap();
    let assignments = federation
        .upstream
        .control(
            Method::GET,
            &format!("/v1/subjects/{}/global-assignments", federation.operator),
            None,
        )
        .await;
    let assignment = assignments.body[0]["id"].as_str().unwrap().to_owned();
    control_ok(
        &federation.upstream,
        Method::DELETE,
        &format!("/v1/assignments/{assignment}"),
        None,
    )
    .await;
    let applied = conclave_server::peering::sync(&down.state, &provider)
        .await
        .unwrap();
    assert!(applied >= 1);
    assert_eq!(
        global_entitlements(&down, &local.to_string()).await,
        json!([])
    );

    // Disabling the subject upstream ends its sessions downstream.
    control_ok(
        &federation.upstream,
        Method::POST,
        &format!("/v1/subjects/{}/disable", federation.operator),
        None,
    )
    .await;
    conclave_server::peering::sync(&down.state, &provider)
        .await
        .unwrap();
    let after = refresh(&down, &signed_in).await;
    assert_eq!(after.code(), "SESSION_ENDED");
    assert_eq!(
        conclave_server::peering::sync(&down.state, &provider)
            .await
            .unwrap(),
        0,
        "nothing new"
    );
}

// r[verify federation.peer.pinning]
#[tokio::test(flavor = "multi_thread")]
async fn pinned_keys_replace_discovered_ones() {
    let federation = upstream().await;
    let pinned = Settings {
        pinned_keys: Some(Arc::new(jsonwebtoken::jwk::JwkSet { keys: vec![] })),
        ..federation.provider()
    };
    let down = downstream(pinned).await;
    let refused = federation.sign_in(&down).await;
    assert_eq!(
        location(&refused),
        format!("{DOWN_RETURN}?error=invalid_id_token"),
        "the upstream's published key isn't pinned"
    );
    let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(
        federation
            .upstream
            .send(Method::GET, "/.well-known/jwks.json", &[], None)
            .await
            .body,
    )
    .unwrap();
    let pinned = Settings {
        pinned_keys: Some(Arc::new(jwks)),
        ..federation.provider()
    };
    let down = downstream(pinned).await;
    let accepted = federation.sign_in(&down).await;
    assert_eq!(location(&accepted), format!("{DOWN_RETURN}?signed_in=true"));
}

// r[verify federation.jwt-bearer]
#[tokio::test(flavor = "multi_thread")]
async fn workloads_exchange_upstream_tokens_for_local_service_principals() {
    let federation = upstream().await;
    let up = &federation.upstream;
    // A CI job's service principal upstream, getting tokens for the
    // downstream (its audience is the downstream's issuer).
    let ci = uuid::Uuid::now_v7();
    control_ok(
        up,
        Method::PUT,
        &format!("/v1/subjects/{ci}"),
        Some(json!({"kind": "service"})),
    )
    .await;
    let register = |audience: &str| {
        json!({
            "kind": "confidential",
            "redirect_uris": ["https://ci.example/unused"],
            "audience": audience,
            "service_subject": ci,
        })
    };
    control_ok(
        up,
        Method::PUT,
        "/v1/oidc/clients/ci",
        Some(register(ISSUER)),
    )
    .await;
    let ci_secret =
        control_ok(up, Method::POST, "/v1/oidc/clients/ci/secret", None).await["client_secret"]
            .as_str()
            .unwrap()
            .to_owned();
    let token = upstream_token(up, &ci_secret).await;

    let workloads = Settings {
        workloads: true,
        ..federation.provider()
    };
    let down = TestApp::with_auth(|auth| {
        auth.identity_providers = Providers::from_settings([workloads]);
        auth.oidc = Some(
            OpenIdProvider::from_pem(
                ID_TOKEN_KEY,
                "https://login.down.example/".into(),
                format!("{ISSUER}/.well-known/jwks.json"),
            )
            .unwrap(),
        );
    })
    .await;
    let unmapped = exchange(&down, &token).await;
    assert_eq!(
        unmapped.body["error"], "invalid_grant",
        "no workload identity yet"
    );

    let deployer = uuid::Uuid::now_v7();
    control_ok(
        &down,
        Method::PUT,
        &format!("/v1/subjects/{deployer}"),
        Some(json!({"kind": "service"})),
    )
    .await;
    control_ok(
        &down,
        Method::POST,
        &format!("/v1/subjects/{deployer}/credentials"),
        Some(json!({"kind": "federated", "provider": "ops", "subject": ci.to_string()})),
    )
    .await;
    let exchanged = exchange(&down, &token).await;
    assert_eq!(exchanged.status, StatusCode::OK, "{:?}", exchanged.body);
    let claims = down
        .verify(exchanged.body["access_token"].as_str().unwrap())
        .await;
    assert_eq!(claims.sub.to_string(), deployer.to_string());
    assert_eq!(claims.amr, ["fed"]);

    // A token for another audience isn't accepted.
    control_ok(
        up,
        Method::PUT,
        "/v1/oidc/clients/ci",
        Some(register("elsewhere")),
    )
    .await;
    let elsewhere = upstream_token(up, &ci_secret).await;
    assert_eq!(
        exchange(&down, &elsewhere).await.body["error"],
        "invalid_grant"
    );

    // People can't be given workload identities.
    let person = down.human("bo@down.example", PASSWORD).await;
    let refused = down
        .control(
            Method::POST,
            &format!("/v1/subjects/{person}/credentials"),
            Some(json!({"kind": "federated", "provider": "ops", "subject": "x"})),
        )
        .await;
    assert_eq!(refused.code(), "INVALID_REQUEST");
}

async fn global_entitlements(app: &TestApp, subject: &str) -> Value {
    app.control(
        Method::GET,
        &format!("/v1/subjects/{subject}/entitlements"),
        None,
    )
    .await
    .body["global"]
        .clone()
}

async fn upstream_token(up: &TestApp, secret: &str) -> String {
    up.send_form(
        "/v1/oauth2/token",
        &[],
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "ci"),
            ("client_secret", secret),
        ],
    )
    .await
    .body["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn exchange(down: &TestApp, token: &str) -> common::Reply {
    down.send_form(
        "/v1/oauth2/token",
        &[],
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", token),
        ],
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_endpoints_only_show_subjects_the_client_has_seen() {
    let federation = upstream().await;
    let up = &federation.upstream;
    let auth = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("down:{}", federation.client_secret)
        )
    );
    // The operator never signed in to `down`, so it's unknown to it.
    let unknown = up
        .send_form(
            "/v1/oauth2/peer/subjects",
            &[("authorization", &auth)],
            &[("subject", &federation.operator)],
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    control_ok(
        up,
        Method::POST,
        &format!("/v1/subjects/{}/disable", federation.operator),
        None,
    )
    .await;
    let events = up
        .send_form(
            "/v1/oauth2/peer/events",
            &[("authorization", &auth)],
            &[("after", "0")],
        )
        .await;
    assert_eq!(events.status, StatusCode::OK, "{:?}", events.body);
    assert!(
        events.body["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["subject"].is_null()),
        "{:?}",
        events.body
    );
    let anonymous = up
        .send_form("/v1/oauth2/peer/events", &[], &[("after", "0")])
        .await;
    assert_eq!(anonymous.body["error"], "invalid_client");
}
