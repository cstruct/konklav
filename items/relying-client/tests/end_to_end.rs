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
use konklav_relying_client::{ClientConfig, ErasureNotice, RelyingClient};
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
    server: Server,
    tenant: uuid::Uuid,
    client: RelyingClient,
    /// How `client` was configured, for starting more clients.
    config: ClientConfig,
    token: String,
    session: String,
    membership: String,
    /// The human the token is for.
    human: String,
}

async fn world() -> World {
    let server = server().await;
    server
        .control(
            Method::PUT,
            "/v1/catalog",
            json!({"actions": [{"name": "project:read"}], "scope_kinds": [{"name": "project"}]}),
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
    let client = RelyingClient::new(config.clone());
    let _tasks = client.start();
    World {
        token: selected["access_token"].as_str().unwrap().to_owned(),
        session: selected["session_id"].as_str().unwrap().to_owned(),
        membership,
        human: human.to_string(),
        client,
        config,
        server,
        tenant,
    }
}

fn reading() -> Requirements {
    Requirements {
        tenant: BTreeSet::from(["project:read".to_owned()]),
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
        Decision::allow()
    );
    until_trusted(&world.client).await;
    assert_eq!(
        world.client.decide(&world.token, &reading()).await.unwrap(),
        Decision::allow()
    );
    let more = Requirements {
        tenant: BTreeSet::from(["document:write".to_owned()]),
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
        Decision::allow()
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
        Decision::allow()
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

/// A client started after a write reaches that write's cursor even when no
/// event follows it, because the stream tells it where it starts.
// r[verify feed.sse.position]
// r[verify relying.feed.position]
#[tokio::test(flavor = "multi_thread")]
async fn clients_started_after_a_write_reach_its_cursor_on_a_quiet_feed() {
    let world = world().await;
    let tenant = uuid::Uuid::now_v7();
    let written = world
        .server
        .control(Method::PUT, &format!("/v1/tenants/{tenant}"), json!({}))
        .await;
    let cursor = Cursor::new(written["cursor"].as_i64().unwrap());
    let late = RelyingClient::new(world.config.clone());
    let _tasks = late.start();
    assert!(late.await_cursor(cursor, Duration::from_secs(5)).await);
}

/// A batch's cursor is awaited like a single write's.
// r[verify platform.batch.results]
#[tokio::test(flavor = "multi_thread")]
async fn batches_are_readable_after_awaiting_their_cursor() {
    let world = world().await;
    until_trusted(&world.client).await;
    let tenant = uuid::Uuid::now_v7();
    let applied = world
        .server
        .control(
            Method::POST,
            "/v1/batch",
            json!({"operations": [
                {"method": "PUT", "path": format!("/tenants/{tenant}"), "body": {}},
                {"method": "POST", "path": format!("/memberships/{}/end", world.membership)},
            ]}),
        )
        .await;
    let cursor = Cursor::new(applied["cursor"].as_i64().unwrap());
    assert!(
        world
            .client
            .await_cursor(cursor, Duration::from_secs(5))
            .await
    );
    assert!(matches!(
        world.client.decide(&world.token, &reading()).await.unwrap(),
        Decision::Deny { .. }
    ));
}

fn reading_document(id: &str) -> Requirements {
    Requirements {
        scopes: vec![konklav_authz::ScopeRequirement {
            tenant: None,
            kind: "document".into(),
            id: id.into(),
            actions: BTreeSet::from(["project:read".to_owned()]),
        }],
        ..Requirements::default()
    }
}

// r[verify relying.cache.registered]
// r[verify relying.cache.registered-debounce]
#[tokio::test(flavor = "multi_thread")]
async fn registered_scopes_are_fetched_and_kept_fresh() {
    let world = world().await;
    until_trusted(&world.client).await;
    world
        .server
        .control(
            Method::PUT,
            "/v1/catalog",
            json!({
                "actions": [{"name": "project:read"}],
                "scope_kinds": [{"name": "project"}, {"name": "document", "registered": true}],
            }),
        )
        .await;
    let recorded = world
        .server
        .control(
            Method::PUT,
            "/v1/registered-scopes/document/d%2F1",
            json!({"tenant": world.tenant}),
        )
        .await;
    let cursor = Cursor::new(recorded["cursor"].as_i64().unwrap());
    assert!(
        world
            .client
            .await_cursor(cursor, Duration::from_secs(5))
            .await
    );
    assert_eq!(
        world
            .client
            .decide(&world.token, &reading_document("d/1"))
            .await
            .unwrap(),
        Decision::allow(),
        "ids are opaque, slashes included"
    );
    assert_eq!(
        world
            .client
            .decide(&world.token, &reading_document("d-9"))
            .await
            .unwrap(),
        Decision::Deny {
            reason: DenyReason::UnknownScope {
                kind: "document".into(),
                id: "d-9".into()
            }
        }
    );

    let removed = world
        .server
        .http
        .delete(format!(
            "http://{}/v1/registered-scopes/document/d%2F1",
            world.server.control
        ))
        .bearer_auth(CONTROL)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let cursor = Cursor::new(removed["cursor"].as_i64().unwrap());
    assert!(
        world
            .client
            .await_cursor(cursor, Duration::from_secs(5))
            .await
    );
    assert_eq!(
        world
            .client
            .decide(&world.token, &reading_document("d/1"))
            .await
            .unwrap(),
        Decision::Deny {
            reason: DenyReason::UnknownScope {
                kind: "document".into(),
                id: "d/1".into()
            }
        }
    );
}

/// Tenant fact requirements, through the check API before the feed is up
/// and locally after, follow the tenant's current facts.
// r[verify authz.decision.tenant-facts]
// r[verify authz.compile.tenant-facts]
// r[verify relying.fallback.equivalence]
#[tokio::test(flavor = "multi_thread")]
async fn tenant_facts_follow_the_tenants_current_facts() {
    let world = world().await;
    world
        .server
        .control(
            Method::PUT,
            "/v1/catalog",
            json!({
                "actions": [{"name": "project:read"}],
                "scope_kinds": [{"name": "project"}],
                "facts": [{"key": "tenant_type", "target": "tenant", "type": "string", "portable": true}],
            }),
        )
        .await;
    let written = world
        .server
        .control(
            Method::PUT,
            &format!("/v1/tenants/{}/facts", world.tenant),
            json!({"tenant_type": "client"}),
        )
        .await;
    let clients: Requirements = serde_json::from_value(json!({
        "tenant": ["project:read"],
        "tenant_facts": {"tenant_type": ["client"]},
    }))
    .unwrap();
    // Possibly before the feed is up, possibly after.
    assert_eq!(
        world.client.decide(&world.token, &clients).await.unwrap(),
        Decision::allow()
    );
    until_trusted(&world.client).await;
    assert!(
        world
            .client
            .await_cursor(
                Cursor::new(written["cursor"].as_i64().unwrap()),
                Duration::from_secs(5)
            )
            .await
    );
    assert_eq!(
        world.client.decide(&world.token, &clients).await.unwrap(),
        Decision::allow()
    );

    let changed = world
        .server
        .control(
            Method::PUT,
            &format!("/v1/tenants/{}/facts", world.tenant),
            json!({"tenant_type": "personal"}),
        )
        .await;
    assert!(
        world
            .client
            .await_cursor(
                Cursor::new(changed["cursor"].as_i64().unwrap()),
                Duration::from_secs(5)
            )
            .await
    );
    // Within the debounce bound the old set may still answer.
    let mut decision = Decision::allow();
    for _ in 0..100 {
        decision = world.client.decide(&world.token, &clients).await.unwrap();
        if decision != Decision::allow() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        decision,
        Decision::Deny {
            reason: DenyReason::TenantFacts {
                fact: "tenant_type".into()
            }
        }
    );
}

/// Accepting a request verifies it once and hands back its claims; one
/// decision follows for it, and a second is refused.
// r[verify relying.verify.accepted-presentation]
#[tokio::test(flavor = "multi_thread")]
async fn accepted_requests_are_decided_once() {
    use konklav_relying_client::{Presented, RequestDescriptor, Verified};

    let world = world().await;
    let presented = Presented {
        request: Some(RequestDescriptor {
            method: "GET".into(),
            url: "https://api.example/projects".into(),
        }),
        ..Presented::bearer(&world.token)
    };
    // Possibly before the feed is up (through the check API), then locally.
    for trusted in [false, true] {
        if trusted {
            until_trusted(&world.client).await;
        }
        let Verified::Valid(accepted) = world.client.accept_request(&presented).await.unwrap()
        else {
            panic!("the token verifies");
        };
        assert_eq!(
            accepted.claims().tid.map(uuid::Uuid::from),
            Some(world.tenant)
        );
        assert_eq!(
            world
                .client
                .decide_accepted(&accepted, &reading())
                .await
                .unwrap(),
            Decision::allow()
        );
        if trusted {
            assert_eq!(
                world
                    .client
                    .decide_accepted(&accepted, &reading())
                    .await
                    .unwrap(),
                Decision::Deny {
                    reason: DenyReason::InvalidToken
                },
                "decided once"
            );
        }
    }
    let verified = world.client.verify_request(&presented).await.unwrap();
    assert!(matches!(verified, Verified::Valid(claims) if claims.sub.to_string().len() == 36));
    assert_eq!(
        world
            .client
            .accept_request(&Presented::bearer("not-a-token"))
            .await
            .unwrap(),
        Verified::Invalid
    );
    let bearer_as_dpop = Presented {
        authorization: format!("DPoP {}", world.token),
        ..presented
    };
    assert_eq!(
        world.client.verify_request(&bearer_as_dpop).await.unwrap(),
        Verified::InvalidProof
    );
}

// r[verify relying.erasure.notify]
// r[verify relying.erasure.reset]
#[tokio::test(flavor = "multi_thread")]
async fn erasures_reach_the_host_live_and_through_the_list() {
    let world = world().await;
    let client = RelyingClient::new(world.config.clone());
    let mut erasures = client.erasures();
    let _tasks = client.start();
    until_trusted(&client).await;
    let next = async |erasures: &mut tokio::sync::mpsc::UnboundedReceiver<ErasureNotice>| {
        tokio::time::timeout(Duration::from_secs(5), erasures.recv())
            .await
            .expect("an erasure notice within 5s")
            .expect("the client is still running")
    };

    // A client that has just started can't know what it missed.
    assert_eq!(
        next(&mut erasures).await,
        ErasureNotice::Missed { since: None }
    );
    assert_eq!(client.erased_subjects(None).await.unwrap(), vec![]);
    assert_eq!(
        client.decide(&world.token, &reading()).await.unwrap(),
        Decision::allow()
    );

    let erased = world
        .server
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/erase", world.human),
            json!({}),
        )
        .await;
    let ErasureNotice::Erased(notice) = next(&mut erasures).await else {
        panic!("expected the erasure");
    };
    assert_eq!(notice.subject.to_string(), world.human);
    // By the time the host hears of it, the client decides nothing from
    // what it had cached about the subject.
    assert_eq!(
        client.decide(&world.token, &reading()).await.unwrap(),
        Decision::Deny {
            reason: DenyReason::InvalidToken
        }
    );
    let cursor = Cursor::new(erased["cursor"].as_i64().unwrap());
    assert!(client.await_cursor(cursor, Duration::from_secs(5)).await);

    // Catching up reads the same erasure, from any time at or before it.
    assert_eq!(client.erased_subjects(None).await.unwrap(), vec![notice]);
    assert_eq!(
        client
            .erased_subjects(Some(notice.erased_at))
            .await
            .unwrap(),
        vec![notice]
    );
    assert_eq!(
        client
            .erased_subjects(Some(notice.erased_at + 3600))
            .await
            .unwrap(),
        vec![]
    );
}
