#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use ed25519_dalek::SigningKey;
use konklav_authz::{Decision, DenyReason, Requirements};
use konklav_core::Cursor;
use konklav_relying::Config;
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
            signer: keys.signer,
            browser: None,
            control_token: Some(CONTROL.into()),
            secrets: konklav_authn::SecretBox::new([]).unwrap(),
            pacing: konklav_server::pacing::Pacing::NONE,
            identity_providers: konklav_server::federation::Providers::default(),
            oidc: None,
            passkeys: None,
        }),
        feed: Arc::new(FeedHub::new(Duration::from_millis(100))),
    };
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listen = Listen {
        subject: any,
        relying: any,
        control: any,
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
    server: Server,
    client: RelyingClient,
    token: String,
    session: String,
    membership: String,
}

async fn world() -> World {
    let server = server().await;
    server
        .control(
            Method::PUT,
            "/v1/catalog",
            json!({"actions": [{"name": "workspace:read"}], "scope_kinds": [{"name": "workspace"}]}),
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
            json!({"policies": [{"action": "workspace:read", "effect": "allow"}]}),
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

    let client = RelyingClient::new(ClientConfig {
        relying_url: format!("http://{}", server.relying),
        subject_url: format!("http://{}", server.subject),
        key_id: key_id.into(),
        secret: secret.into(),
        core: Config {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            ..Config::default()
        },
    });
    let _tasks = client.start();
    World {
        token: selected["access_token"].as_str().unwrap().to_owned(),
        session: selected["session_id"].as_str().unwrap().to_owned(),
        membership,
        client,
        server,
    }
}

fn reading() -> Requirements {
    Requirements {
        tenant: BTreeSet::from(["workspace:read".to_owned()]),
        ..Requirements::default()
    }
}

async fn until_trusted(client: &RelyingClient) {
    for _ in 0..200 {
        if client.is_trusted() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the feed never connected");
}

// r[verify relying.fallback.equivalence]
#[tokio::test(flavor = "multi_thread")]
async fn decides_before_and_after_the_feed_connects() {
    let world = world().await;
    // Possibly before the feed is up: answered through the check API.
    assert_eq!(
        world.client.decide(&world.token, &reading()).await.unwrap(),
        Decision::Allow
    );
    until_trusted(&world.client).await;
    assert_eq!(
        world.client.decide(&world.token, &reading()).await.unwrap(),
        Decision::Allow
    );
    let more = Requirements {
        tenant: BTreeSet::from(["workspace:write".to_owned()]),
        ..Requirements::default()
    };
    assert!(matches!(
        world.client.decide(&world.token, &more).await.unwrap(),
        Decision::Deny {
            reason: DenyReason::MissingActions { .. }
        }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_sessions_are_denied_through_the_feed() {
    let world = world().await;
    until_trusted(&world.client).await;
    assert_eq!(
        world.client.decide(&world.token, &reading()).await.unwrap(),
        Decision::Allow
    );
    let revoked = world
        .server
        .control(
            Method::POST,
            "/v1/sessions/revoke",
            json!({"session": world.session}),
        )
        .await;
    let cursor = Cursor::new(revoked["cursor"].as_i64().unwrap());
    assert!(
        world
            .client
            .await_cursor(cursor, Duration::from_secs(5))
            .await
    );
    assert_eq!(
        world.client.decide(&world.token, &reading()).await.unwrap(),
        Decision::Deny {
            reason: DenyReason::InvalidToken
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_are_readable_after_awaiting_their_cursor() {
    let world = world().await;
    until_trusted(&world.client).await;
    assert_eq!(
        world.client.decide(&world.token, &reading()).await.unwrap(),
        Decision::Allow
    );
    let detail = world
        .server
        .http
        .get(format!(
            "http://{}/v1/memberships/{}",
            world.server.control, world.membership
        ))
        .bearer_auth(CONTROL)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let assignment = detail["assignments"][0]["id"].as_str().unwrap();
    let removed = world
        .server
        .control(
            Method::DELETE,
            &format!("/v1/assignments/{assignment}"),
            json!({}),
        )
        .await;
    let cursor = Cursor::new(removed["cursor"].as_i64().unwrap());
    assert!(
        world
            .client
            .await_cursor(cursor, Duration::from_secs(5))
            .await
    );
    assert!(matches!(
        world.client.decide(&world.token, &reading()).await.unwrap(),
        Decision::Deny {
            reason: DenyReason::MissingActions { .. }
        }
    ));
}
