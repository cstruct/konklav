//! The client against a scripted Konklav: what it does when Konklav
//! refuses, fails, stalls or redirects.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use konklav_authz::{Decision, DenyReason, Requirements};
use konklav_core::{SessionId, SubjectId, TenantId};
use konklav_relying::Config;
use konklav_relying_client::{ClientConfig, Presented, RelyingClient, RequestDescriptor, Verified};
use konklav_test_support::DpopKey;
use konklav_token::{AccessClaims, Confirmation, Signer, TokenKind};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const URL: &str = "https://api.example/projects/1";
const SECRET: &str = "the-secret-key";

/// An answer: its status, a `Location` if it redirects, and its JSON body.
type Answer = (u16, Option<String>, Value);

/// A Konklav that answers each request with what `script` says, and keeps
/// the requests it got as `(path, body)`.
struct Fake {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

impl Fake {
    async fn new(script: impl Fn(&str, usize) -> Answer + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let script = Arc::new(script);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, seen.clone(), script.clone()));
            }
        });
        Self { address, requests }
    }

    fn paths(&self) -> Vec<String> {
        let requests = self.requests.lock().unwrap();
        requests.iter().map(|(path, _)| path.clone()).collect()
    }

    fn client(&self, capacity: usize) -> RelyingClient {
        RelyingClient::new(ClientConfig {
            relying_url: format!("http://{}", self.address),
            subject_url: format!("http://{}", self.address),
            key_id: "key".into(),
            secret: SECRET.into(),
            core: Config {
                issuer: "https://auth.example".into(),
                audiences: vec!["api".into()],
                dpop_replay_capacity: capacity,
                ..Config::default()
            },
        })
    }
}

/// Serves one request per connection.
async fn serve(
    mut stream: TcpStream,
    seen: Arc<Mutex<Vec<(String, String)>>>,
    script: Arc<impl Fn(&str, usize) -> Answer>,
) {
    let mut request = Vec::new();
    let mut chunk = [0; 4096];
    let (head, body) = loop {
        let Ok(read @ 1..) = stream.read(&mut chunk).await else {
            return;
        };
        request.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&request);
        let Some((head, body)) = text.split_once("\r\n\r\n") else {
            continue;
        };
        let length = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")?
                    .trim()
                    .parse()
                    .ok()
            })
            .unwrap_or(0);
        if body.len() >= length {
            break (head.to_owned(), body.to_owned());
        }
    };
    let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
    let nth = {
        let mut seen = seen.lock().unwrap();
        seen.push((path.clone(), body));
        seen.iter().filter(|(seen, _)| *seen == path).count()
    };
    let (status, location, body) = script(&path, nth);
    let body = body.to_string();
    let location = location.map_or_else(String::new, |to| format!("location: {to}\r\n"));
    let answer = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n{location}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(answer.as_bytes()).await;
}

fn login() -> Answer {
    (
        200,
        None,
        json!({"access_token": "service", "expires_in": 900}),
    )
}

fn decision(decision: &Decision) -> Answer {
    (200, None, serde_json::to_value(decision).unwrap())
}

const INVALID: Decision = Decision::Deny {
    reason: DenyReason::InvalidToken,
};

fn now() -> i64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    i64::try_from(now.as_secs()).unwrap()
}

/// A token bound to `key`. The scripted Konklav decides whether it is valid.
fn token(key: &DpopKey) -> String {
    Signer::new(SigningKey::from_bytes(&[9; 32])).sign(&AccessClaims {
        iss: "https://auth.example".into(),
        aud: "api".into(),
        sub: SubjectId::new_v7(),
        jti: "j".into(),
        iat: now(),
        exp: now() + 900,
        knd: TokenKind::Tenant,
        sid: SessionId::new_v7(),
        cid: None,
        sv: 1,
        amr: vec!["pwd".into()],
        auth_time: now(),
        tid: Some(TenantId::new_v7()),
        mid: None,
        sfl: vec![],
        fct: BTreeMap::new(),
        act: None,
        cnf: Some(Confirmation { jkt: key.jkt() }),
    })
}

fn presented(key: &DpopKey, token: &str) -> Presented {
    Presented {
        authorization: format!("DPoP {token}"),
        dpop: Some(key.proof("GET", URL, Some(token))),
        request: Some(RequestDescriptor {
            method: "GET".into(),
            url: URL.into(),
        }),
    }
}

// With room for one presentation, one that stayed held would refuse the
// next request.
// r[verify relying.verify.accepted-presentation]
#[tokio::test]
async fn presentations_the_check_api_refuses_or_fails_are_released() {
    let fake = Fake::new(|path, nth| match (path, nth) {
        ("/v1/login/secret-key", _) => login(),
        ("/v1/check", 1) => decision(&INVALID),
        ("/v1/check", 2) => (500, None, json!({})),
        _ => decision(&Decision::allow()),
    })
    .await;
    let client = fake.client(1);
    let key = DpopKey::new(1);
    let token = token(&key);

    let refused = client.accept_request(&presented(&key, &token)).await;
    assert_eq!(refused.unwrap(), Verified::Invalid);
    let failed = client.accept_request(&presented(&key, &token)).await;
    assert!(failed.is_err(), "the check API failed");
    let accepted = client.accept_request(&presented(&key, &token)).await;
    assert!(
        matches!(accepted.unwrap(), Verified::Valid(_)),
        "the earlier presentations are still held"
    );
    // The accepted one is held until it is released.
    let full = client.accept_request(&presented(&key, &token)).await;
    assert_eq!(full.unwrap(), Verified::InvalidProof);
}

// r[verify relying.verify.dpop-replay]
// r[verify relying.verify.dpop-before-check]
#[tokio::test]
async fn a_proof_the_check_api_decided_with_is_refused_again() {
    let fake = Fake::new(|path, nth| match (path, nth) {
        ("/v1/login/secret-key", _) => login(),
        ("/v1/check", 1) => decision(&INVALID),
        _ => decision(&Decision::allow()),
    })
    .await;
    let client = fake.client(1);
    let key = DpopKey::new(1);
    let token = token(&key);
    let any = Requirements::default();
    let replayed = Decision::Deny {
        reason: DenyReason::InvalidDpopProof,
    };

    // A proof for a token the check API refuses takes none of the room.
    let garbage = presented(&key, &token);
    assert_eq!(
        client.decide_request(&garbage, &any).await.unwrap(),
        INVALID
    );

    let once = presented(&key, &token);
    let allowed = client.decide_request(&once, &any).await.unwrap();
    assert_eq!(allowed, Decision::allow());
    assert_eq!(client.decide_request(&once, &any).await.unwrap(), replayed);
    assert_eq!(
        client.verify_request(&once).await.unwrap(),
        Verified::InvalidProof
    );
    assert_eq!(
        client.accept_request(&once).await.unwrap(),
        Verified::InvalidProof
    );
}

// r[verify item.relying-client.http]
#[tokio::test]
async fn redirects_are_not_followed_with_the_secret() {
    let fake = Fake::new(|path, _| match path {
        "/v1/login/secret-key" => (307, Some("/elsewhere".into()), json!({})),
        _ => login(),
    })
    .await;
    let client = fake.client(1);
    let decided = client.decide("token", &Requirements::default()).await;
    assert!(decided.is_err(), "fails closed");
    assert_eq!(fake.paths(), ["/v1/login/secret-key"]);
}

// r[verify item.relying-client.http]
#[tokio::test(start_paused = true)]
async fn a_konklav_that_never_answers_fails_the_decision() {
    // Accepts connections and says nothing.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = Fake {
        address,
        requests: Arc::default(),
    };
    let client = fake.client(1);
    let started = tokio::time::Instant::now();
    let decided = client.decide("token", &Requirements::default()).await;
    assert!(decided.is_err(), "fails closed");
    assert!(started.elapsed() <= Duration::from_secs(11));
    drop(listener);
}

// r[verify item.relying-client.http]
#[test]
fn the_secret_stays_out_of_debug_output() {
    let config = ClientConfig {
        relying_url: "http://konklav:8081".into(),
        subject_url: "http://konklav:8080".into(),
        key_id: "key".into(),
        secret: SECRET.into(),
        core: Config::default(),
    };
    let shown = format!("{config:?}");
    assert!(shown.contains("key_id: \"key\""), "{shown}");
    assert!(!shown.contains(SECRET), "{shown}");
}

// r[verify item.relying-client.invites]
#[tokio::test]
async fn a_tenants_invites_are_made_listed_and_revoked_as_the_service_principal() {
    const TENANT: &str = "01900000-0000-7000-8000-000000000001";
    const INVITE: &str = "01900000-0000-7000-8000-0000000000aa";
    // The client names the tenant and the invite as percent-encoded path
    // segments, as Konklav decodes them.
    let fake = Fake::new(|path, _| match path.replace("%2D", "-").as_str() {
        "/v1/login/secret-key" => login(),
        p if p == format!("/v1/tenants/{TENANT}/invites") => (
            201,
            None,
            json!({"invite_id": INVITE, "expires_at": "2026-11-26T12:00:00Z", "token": "secret.link", "cursor": "1"}),
        ),
        p if p.starts_with(&format!("/v1/tenants/{TENANT}/invites?")) => (
            200,
            None,
            json!({"invites": [{
                "id": INVITE, "email": null, "tenant": TENANT, "roles": ["viewer"],
                "membership": null, "state": "pending", "expires_at": "2026-11-26T12:00:00Z",
                "consumed_at": null, "metadata": {}, "metadata_etag": "e",
                "public_metadata": {}, "sign_up": true,
            }], "next": null}),
        ),
        p if p == format!("/v1/tenants/{TENANT}/invites/{INVITE}/revoke") => (
            409,
            None,
            json!({"error": {"code": "CONFLICT", "message": "the invite was already redeemed"}}),
        ),
        _ => (404, None, json!({})),
    })
    .await;
    let client = fake.client(1);
    let made = client
        .create_invite(
            TENANT,
            &konklav_relying_client::invites::NewInvite {
                roles: vec!["viewer".into()],
                sign_up: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(made.token, "secret.link");
    let sent = fake.requests.lock().unwrap().last().unwrap().1.clone();
    assert_eq!(
        serde_json::from_str::<Value>(&sent).unwrap(),
        json!({"roles": ["viewer"], "sign_up": true})
    );

    let page = client.invites(TENANT, None, Some(10)).await.unwrap();
    assert_eq!(page.invites.len(), 1);
    assert!(page.invites[0].sign_up);
    assert_eq!(
        fake.paths().last().unwrap().replace("%2D", "-"),
        format!("/v1/tenants/{TENANT}/invites?limit=10")
    );

    // A refusal is Konklav's status and body.
    let refused = client
        .revoke_invite(TENANT, INVITE.parse().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused,
            konklav_relying_client::Error::Status { status: 409, .. }
        ),
        "{refused:?}"
    );
    // A tenant that would name another path is never asked for.
    let asked = fake.paths().len();
    assert!(client.invites("..", None, None).await.is_err());
    assert_eq!(fake.paths().len(), asked);
}
