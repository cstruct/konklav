//! The single sign-on example's services in Rust, one binary each. They
//! behave like the Python ones in `../python` and serve the same browser
//! files from `../web`; see `examples/sso-compose/README.md`.
//!
//! This library holds what they share: DPoP proofs, the browser files,
//! the relying client's setup and a few helpers.

pub mod dpop;
pub mod web;

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use konklav_relying::Config;
use konklav_relying_client::{ClientConfig, RelyingClient};
use serde::Deserialize;
use serde_json::Value;

/// An environment variable the service needs.
///
/// # Panics
///
/// If it isn't set: the service can't start without it.
#[must_use]
pub fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

/// `bytes` random bytes, base64url-encoded.
///
/// # Panics
///
/// If the system has no randomness.
#[must_use]
pub fn random_token(bytes: usize) -> String {
    let mut buffer = vec![0; bytes];
    getrandom::fill(&mut buffer).expect("system randomness");
    URL_SAFE_NO_PAD.encode(buffer)
}

/// What the setup service wrote for the apps.
#[derive(Clone, Debug, Deserialize)]
pub struct Secrets {
    pub app_api_key: String,
    pub admin_api_key: String,
    pub admin_client_secret: String,
}

/// Reads `SECRETS_FILE`.
///
/// # Panics
///
/// If it can't be read: the setup service hasn't run.
#[must_use]
pub fn secrets() -> Secrets {
    let path = env("SECRETS_FILE");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

/// A JWT's claims, *without verifying it*. Only for tokens just received
/// from Konklav's token endpoint, or after the relying client verified it.
#[must_use]
pub fn claims_of(jwt: &str) -> Option<Value> {
    let payload = jwt.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// A relying client for `audience`, following Konklav's change feed as the
/// service principal whose secret key is `key` (`<key id>.<secret>`).
/// Returns once its caches can be trusted, or after half a minute.
///
/// # Panics
///
/// If `key` isn't `<key id>.<secret>`, or the environment lacks Konklav's
/// URLs or the issuer.
pub async fn relying_client(audience: &str, key: &str) -> RelyingClient {
    let (key_id, secret) = key
        .split_once('.')
        .expect("a secret key is <key id>.<secret>");
    let client = RelyingClient::new(ClientConfig {
        relying_url: env("KONKLAV_RELYING_URL"),
        subject_url: env("KONKLAV_SUBJECT_URL"),
        key_id: key_id.into(),
        secret: secret.into(),
        core: Config {
            issuer: env("ISSUER"),
            audience: audience.into(),
            ..Config::default()
        },
    });
    // Detached: the background tasks run as long as the service.
    drop(client.start());
    for _ in 0..300 {
        if client.is_trusted() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("following Konklav's change feed");
    client
}

/// Serves `router` on every interface at `port` until the process stops.
///
/// # Panics
///
/// If the port can't be bound.
pub async fn serve(router: axum::Router, port: u16) {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| panic!("binding port {port}: {e}"));
    println!("listening on port {port}");
    axum::serve(listener, router).await.expect("serving");
}
