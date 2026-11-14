//! A relying system on axum against a real Konklav server: route
//! policies, extractors and a rate limit, decided by a real
//! `RelyingClient`.
#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use chrono::Duration as ChronoDuration;
use ed25519_dalek::SigningKey;
use konklav_authz::{Decision, Requirements};
use konklav_axum::{
    ClientAddress, Konklav, Policy, RequestDecider, RoutePolicy, RouteRateLimit, RouterPolicy,
    TenantToken,
};
use konklav_relying::Config;
use konklav_relying_client::rate_limit::{RateLimit, RateLimitConfig, RateLimitWindow};
use konklav_relying_client::{ClientConfig, RelyingClient};
use konklav_server::config::Listen;
use konklav_server::feed::FeedHub;
use konklav_server::keys::ConfiguredKeys;
use konklav_server::serve::BoundServer;
use konklav_server::surface::Surface;
use konklav_server::{AppState, AuthContext};
use konklav_test_support::TestDatabase;
use konklav_token::Signer;
use reqwest::Method;
use serde_json::{Value, json};

const ISSUER: &str = "https://auth.example";
const AUDIENCE: &str = "api";
const CONTROL: &str = "control-token";
const PASSWORD: &str = "correct horse battery";

struct Server {
    _db: TestDatabase,
    subject: SocketAddr,
    relying: SocketAddr,
    control: SocketAddr,
    http: reqwest::Client,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn server() -> Server {
    let db = TestDatabase::new().await;
    let keys = ConfiguredKeys {
        signer: Signer::new(SigningKey::from_bytes(&[5; 32])),
        published: vec![SigningKey::from_bytes(&[5; 32]).verifying_key()],
    };
    keys.sync(&mut db.pool().get().await.unwrap())
        .await
        .unwrap();
    let state = AppState {
        pool: db.pool().clone(),
        auth: Arc::new(AuthContext {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            access_ttl: ChronoDuration::minutes(15),
            session_lifetime: ChronoDuration::days(1),
            hasher: konklav_authn::PasswordHasher::new(8, 1, 1).unwrap(),
            hashing_slots: AuthContext::default_hashing_slots(),
            signer: keys.signer,
            browser: None,
            control_token: Some(CONTROL.into()),
            control_token_expires_at: None,
            secrets: konklav_authn::SecretBox::new([]).unwrap(),
            pacing: konklav_server::pacing::Pacing::NONE,
            identity_providers: konklav_server::federation::Providers::default(),
            oidc: None,
            passkeys: None,
            trusted_proxies: Vec::new(),
            batches: konklav_server::batch_api::BatchLimits::DEFAULT,
            metadata_limit: konklav_server::metadata::DEFAULT_LIMIT,
            dpop_urls: Vec::new(),
        }),
        feed: Arc::new(FeedHub::new(Duration::from_millis(100))),
    };
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listen = Listen {
        subject: any,
        relying: any,
        control: any,
        trusted_proxies: Vec::new(),
    };
    let bound = BoundServer::bind(&listen, state.clone()).await.unwrap();
    let addrs = bound.local_addrs().unwrap();
    let addr = |surface| addrs.iter().find(|(_, s)| s.contains(&surface)).unwrap().0;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(konklav_server::feed::listen(
        db.url().to_owned(),
        state.feed.clone(),
    ));
    tokio::spawn(bound.run(async move {
        let _ = stopped.await;
    }));
    Server {
        subject: addr(Surface::Subject),
        relying: addr(Surface::Relying),
        control: addr(Surface::Control),
        http: reqwest::Client::new(),
        _db: db,
        _stop: stop,
    }
}

impl Server {
    async fn control(&self, method: Method, path: &str, body: Value) -> Value {
        let response = self
            .http
            .request(method, format!("http://{}{path}", self.control))
            .bearer_auth(CONTROL)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{path}: {}",
            response.status()
        );
        response.json().await.unwrap()
    }

    async fn subject(&self, path: &str, bearer: Option<&str>, body: Value) -> Value {
        let mut request = self
            .http
            .post(format!("http://{}{path}", self.subject))
            .json(&body);
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        let response = request.send().await.unwrap();
        assert!(
            response.status().is_success(),
            "{path}: {}",
            response.status()
        );
        response.json().await.unwrap()
    }
}

struct World {
    // Keeps the server running for the test.
    _server: Server,
    tenant: uuid::Uuid,
    client: RelyingClient,
    token: String,
}

async fn world() -> World {
    let server = server().await;
    server
        .control(
            Method::PUT,
            "/v1/catalog",
            json!({
                "actions": [
                    {"name": "project:read"},
                    {"name": "user:manage_data", "vouches": ["user:write"]},
                    {"name": "user:write"},
                ],
                "scope_kinds": [{"name": "project"}],
            }),
        )
        .await;
    let tenant = uuid::Uuid::now_v7();
    server
        .control(Method::PUT, &format!("/v1/tenants/{tenant}"), json!({}))
        .await;
    server
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}/roles/reader"),
            json!({"policies": [{"action": "project:read", "effect": "allow"}]}),
        )
        .await;
    // Manages user data, which vouches for `user:write`, while
    // `user:write` itself is denied.
    server
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}/roles/steward"),
            json!({"policies": [
                {"action": "user:manage_data", "effect": "allow"},
                {"action": "user:write", "effect": "deny"},
            ]}),
        )
        .await;

    let human = uuid::Uuid::now_v7();
    server
        .control(
            Method::PUT,
            &format!("/v1/subjects/{human}"),
            json!({"kind": "human"}),
        )
        .await;
    server
        .control(
            Method::POST,
            &format!("/v1/subjects/{human}/credentials"),
            json!({"kind": "password", "identifier": "ada@example.com", "password": PASSWORD}),
        )
        .await;
    let membership = uuid::Uuid::now_v7().to_string();
    server
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            json!({"subject": human, "tenant": tenant}),
        )
        .await;
    server
        .control(
            Method::POST,
            &format!("/v1/memberships/{membership}/assignments"),
            json!({"role": "reader"}),
        )
        .await;
    server
        .control(
            Method::POST,
            &format!("/v1/memberships/{membership}/assignments"),
            json!({"role": "steward"}),
        )
        .await;

    let service = uuid::Uuid::now_v7();
    server
        .control(
            Method::PUT,
            &format!("/v1/subjects/{service}"),
            json!({"kind": "service"}),
        )
        .await;
    let key = server
        .control(
            Method::POST,
            &format!("/v1/subjects/{service}/credentials"),
            json!({"kind": "secret_key"}),
        )
        .await;
    let (key_id, secret) = key["secret_keys"]["a"]
        .as_str()
        .unwrap()
        .split_once('.')
        .unwrap();

    let login = server
        .subject(
            "/v1/login/password",
            None,
            json!({"identifier": "ada@example.com", "password": PASSWORD}),
        )
        .await;
    let identity = login["access_token"].as_str().unwrap().to_owned();
    let selected = server
        .subject(
            "/v1/login/tenant",
            Some(&identity),
            json!({"tenant": tenant}),
        )
        .await;

    let config = ClientConfig {
        relying_url: format!("http://{}", server.relying),
        subject_url: format!("http://{}", server.subject),
        key_id: key_id.into(),
        secret: secret.into(),
        core: Config {
            issuer: ISSUER.into(),
            audiences: vec![AUDIENCE.into()],
            ..Config::default()
        },
    };
    let client = RelyingClient::new(config);
    let _tasks = client.start();
    World {
        token: selected["access_token"].as_str().unwrap().to_owned(),
        client,
        _server: server,
        tenant,
    }
}

async fn tenant_of(token: TenantToken) -> String {
    token
        .tid
        .map(|tenant| tenant.to_string())
        .unwrap_or_default()
}

async fn address(ClientAddress(address): ClientAddress) -> String {
    address.to_string()
}

/// Whether the handler's own check for `user:write` passes.
async fn writes(decider: RequestDecider) -> String {
    let write = Requirements {
        tenant: BTreeSet::from(["user:write".to_owned()]),
        ..Requirements::default()
    };
    let decision = decider.decide(&write).await.unwrap();
    format!("user:write: {}", matches!(decision, Decision::Allow { .. }))
}

/// The relying system: projects need `project:read`, documents also need
/// `document:write`, which nobody has, and the address route is public and
/// rate limited per client. `/users/data` needs `user:manage_data`, and
/// `/users` and `/projects/{project}/users` check `user:write` in their
/// handler; `/users` also needs it itself.
fn relying_system(client: RelyingClient) -> Router {
    let konklav = Konklav::builder(client).build().unwrap();
    let projects = RouterPolicy::new(Policy::new().tenant_actions(["project:read"]));
    let per_client = RouteRateLimit::new(
        RateLimit::new(RateLimitConfig::new(
            "address",
            vec![RateLimitWindow {
                size: 1,
                period_ms: 60_000,
            }],
        ))
        .unwrap(),
        "{client:address}",
    )
    .unwrap();
    Router::new()
        .route(
            "/projects/{project}",
            get(tenant_of).route_layer(
                projects
                    .route(&Policy::new().scope_actions("project", ["project:read"]))
                    .unwrap(),
            ),
        )
        .route(
            "/projects/{project}/documents",
            get(tenant_of).route_layer(
                projects
                    .route(&Policy::new().tenant_actions(["document:write"]))
                    .unwrap(),
            ),
        )
        .route(
            "/users/data",
            get(writes).route_layer(
                RoutePolicy::new(&Policy::new().tenant_actions(["user:manage_data"])).unwrap(),
            ),
        )
        .route(
            "/users",
            get(writes).route_layer(
                RoutePolicy::new(&Policy::new().tenant_actions(["user:write"])).unwrap(),
            ),
        )
        .route(
            "/projects/{project}/users",
            get(writes).route_layer(
                projects
                    .route(&Policy::new().scope_actions("project", ["project:read"]))
                    .unwrap(),
            ),
        )
        .route(
            "/address",
            get(address).route_layer(RoutePolicy::public().rate_limit(per_client).unwrap()),
        )
        .layer(konklav.layer())
}

// r[verify item.axum.relying-host]
// r[verify item.axum.single-decision]
// r[verify item.axum.outcomes]
// r[verify item.axum.rate-limited]
// r[verify item.axum.request-decider]
#[tokio::test(flavor = "multi_thread")]
async fn a_relying_system_on_axum_decides_through_konklav() {
    let world = world().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        axum::serve(
            listener,
            relying_system(world.client.clone())
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .into_future(),
    );
    let http = reqwest::Client::new();
    let get = |path: &str, token: Option<&str>| {
        let mut request = http.get(format!("http://{addr}{path}"));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send()
    };

    // Possibly through the check API before the feed is up, then locally.
    for _ in 0..2 {
        let allowed = get("/projects/p-1", Some(&world.token)).await.unwrap();
        assert_eq!(allowed.status(), 200);
        assert_eq!(allowed.text().await.unwrap(), world.tenant.to_string());
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let forbidden = get("/projects/p-1/documents", Some(&world.token))
        .await
        .unwrap();
    assert_eq!(forbidden.status(), 403);
    assert_eq!(
        forbidden.json::<Value>().await.unwrap(),
        json!({"error": {"code": "forbidden", "reason": {"missing_actions": {"actions": ["document:write"]}}}})
    );

    let missing = get("/projects/p-1", None).await.unwrap();
    assert_eq!(missing.status(), 401);
    assert_eq!(missing.headers()["www-authenticate"], "Bearer, DPoP");
    let invalid = get("/projects/p-1", Some("not-a-token")).await.unwrap();
    assert_eq!(invalid.status(), 401);
    assert_eq!(
        invalid.headers()["www-authenticate"],
        r#"Bearer error="invalid_token""#
    );

    // A route requiring `user:manage_data` vouches for its handler's
    // `user:write` check, despite the deny; a route requiring only
    // `project:read` doesn't, and a route requiring `user:write` itself is
    // still forbidden.
    // r[verify relying.verify.route-authority]
    let vouched = get("/users/data", Some(&world.token)).await.unwrap();
    assert_eq!(vouched.status(), 200);
    assert_eq!(vouched.text().await.unwrap(), "user:write: true");
    let unvouched = get("/projects/p-1/users", Some(&world.token))
        .await
        .unwrap();
    assert_eq!(unvouched.status(), 200);
    assert_eq!(unvouched.text().await.unwrap(), "user:write: false");
    let direct = get("/users", Some(&world.token)).await.unwrap();
    assert_eq!(direct.status(), 403);
    assert_eq!(
        direct.json::<Value>().await.unwrap(),
        json!({"error": {"code": "forbidden", "reason": {"missing_actions": {"actions": ["user:write"]}}}})
    );

    let first = get("/address", None).await.unwrap();
    assert_eq!(first.status(), 200);
    assert_eq!(first.text().await.unwrap(), "127.0.0.1");
    let limited = get("/address", None).await.unwrap();
    assert_eq!(limited.status(), 429);
    assert!(limited.headers().contains_key("retry-after"));
}
