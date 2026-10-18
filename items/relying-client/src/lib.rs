//! The native Rust host binding for the relying core.
//!
//! [`RelyingClient`] owns a [`Relying`] core and does its I/O on tokio:
//!
//! - It logs in as a service principal with a secret key and keeps a token.
//! - It keeps the change feed (SSE) connected, resuming by cursor.
//! - It runs the core's background work: refreshing JWKS and entitlement
//!   sets before they are needed.
//! - It answers [`RelyingClient::decide`] from the core, fetching whatever
//!   the core still needs, or asking `/v1/check` when the core says the
//!   caches can't be trusted.
//!
//! The decision rules live in `konklav-relying`; this crate only moves bytes.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use konklav_authz::{Decision, EntitlementSet, Requirements};
use konklav_core::Cursor;
use konklav_core::feed::{FeedEvent, SessionChanged};
use konklav_relying::{Config, Key, Need, Outcome, Relying};
use konklav_token::JwkSet;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::Notify;

/// Where Conclave is and how to authenticate to it.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Base URL of the relying surface, such as `https://conclave:8081`.
    pub relying_url: String,
    /// Base URL of the subject-facing surface, for the service login.
    pub subject_url: String,
    /// The service principal's secret-key credential id and secret.
    pub key_id: String,
    pub secret: String,
    pub core: Config,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("conclave answered {status}: {body}")]
    Status { status: u16, body: String },
    #[error("could not reach a decision")]
    Exhausted,
}

/// The current time in Unix milliseconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

struct ServiceToken {
    token: String,
    refresh_at: u64,
}

struct Inner {
    config: ClientConfig,
    core: Mutex<Relying>,
    http: reqwest::Client,
    token: tokio::sync::Mutex<Option<ServiceToken>>,
    wake: Notify,
}

/// A relying client. Cheap to clone; clones share caches.
#[derive(Clone)]
pub struct RelyingClient {
    inner: Arc<Inner>,
}

#[derive(Deserialize)]
struct LoginResponse {
    access_token: String,
    expires_in: u64,
}

impl RelyingClient {
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        let core = Relying::new(config.core.clone());
        Self {
            inner: Arc::new(Inner {
                config,
                core: Mutex::new(core),
                http: reqwest::Client::new(),
                token: tokio::sync::Mutex::new(None),
                wake: Notify::new(),
            }),
        }
    }

    /// Starts the feed and background work. They run until the returned
    /// handles are aborted.
    #[must_use]
    pub fn start(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let feed = self.clone();
        let work = self.clone();
        vec![
            tokio::spawn(async move { feed.run_feed().await }),
            tokio::spawn(async move { work.run_work().await }),
        ]
    }

    fn core(&self) -> std::sync::MutexGuard<'_, Relying> {
        self.inner
            .core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A bearer token for the relying surface, logging in when needed.
    async fn bearer(&self) -> Result<String, Error> {
        let mut token = self.inner.token.lock().await;
        if let Some(current) = token.as_ref()
            && current.refresh_at > now()
        {
            return Ok(current.token.clone());
        }
        let response = self
            .inner
            .http
            .post(format!(
                "{}/v1/login/secret-key",
                self.inner.config.subject_url
            ))
            .json(&serde_json::json!({
                "key_id": self.inner.config.key_id,
                "secret": self.inner.config.secret,
            }))
            .send()
            .await?;
        let login: LoginResponse = checked(response).await?.json().await?;
        let lifetime = login.expires_in.saturating_mul(1000);
        *token = Some(ServiceToken {
            token: login.access_token.clone(),
            // Renew at 80% of the lifetime.
            refresh_at: now() + lifetime / 5 * 4,
        });
        Ok(login.access_token)
    }

    async fn get(&self, path: &str) -> Result<reqwest::Response, Error> {
        let url = format!("{}{path}", self.inner.config.relying_url);
        let response = self
            .inner
            .http
            .get(url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await?;
        Ok(response)
    }

    /// Decides `requirements` for an access token presented to the relying
    /// system. Fails closed: an error means deny.
    // r[impl relying.decision.fail-closed]
    pub async fn decide(
        &self,
        token: &str,
        requirements: &Requirements,
    ) -> Result<Decision, Error> {
        for _ in 0..4 {
            let outcome = self.core().decide(token, requirements, None, now());
            let needs = match outcome {
                Outcome::Decided { decision } => return Ok(decision),
                Outcome::Need { needs } => needs,
            };
            if needs.contains(&Need::Check) {
                return self.check(token, requirements).await;
            }
            let results =
                futures_util::future::join_all(needs.iter().map(|need| self.fetch(need))).await;
            if let Some(error) = results.into_iter().find_map(Result::err) {
                return Err(error);
            }
        }
        Err(Error::Exhausted)
    }

    /// Asks Conclave's check API, for when local caches can't be trusted.
    async fn check(&self, token: &str, requirements: &Requirements) -> Result<Decision, Error> {
        let url = format!("{}/v1/check", self.inner.config.relying_url);
        let response = self
            .inner
            .http
            .post(url)
            .bearer_auth(self.bearer().await?)
            .json(&serde_json::json!({"token": token, "requirements": requirements}))
            .send()
            .await?;
        match Relying::from_check(checked(response).await?.json::<Decision>().await?) {
            Outcome::Decided { decision } => Ok(decision),
            Outcome::Need { .. } => Err(Error::Exhausted),
        }
    }

    /// Fetches one thing the core needs and hands it over.
    async fn fetch(&self, need: &Need) -> Result<(), Error> {
        let result = self.fetch_inner(need).await;
        if result.is_err() {
            self.core().on_fetch_failed(need);
        }
        result
    }

    async fn fetch_inner(&self, need: &Need) -> Result<(), Error> {
        match need {
            Need::Jwks => {
                let jwks: JwkSet = checked(self.get("/.well-known/jwks.json").await?)
                    .await?
                    .json()
                    .await?;
                self.core().on_jwks(jwks, now());
            }
            Need::Session { session } => {
                let response = self.get(&format!("/v1/session-states/{session}")).await?;
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    self.core().on_session_unknown(*session);
                } else {
                    let state: SessionChanged = checked(response).await?.json().await?;
                    self.core().on_session(state);
                }
            }
            Need::Entitlements { key } => {
                let set: EntitlementSet = checked(self.get(&entitlements_path(key)).await?)
                    .await?
                    .json()
                    .await?;
                self.core().on_entitlements(set, now());
            }
            Need::Check => {}
        }
        Ok(())
    }

    /// Waits until the client reflects every change up to `cursor` (a write
    /// response's cursor), or the timeout passes. Returns whether it caught
    /// up.
    pub async fn await_cursor(&self, cursor: Cursor, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.core().await_cursor(cursor) {
                return true;
            }
            self.inner.wake.notify_waiters();
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn run_work(&self) {
        loop {
            let work = self.core().poll_work(now());
            for need in &work.fetch {
                if let Err(error) = self.fetch(need).await {
                    tracing::warn!(%error, ?need, "background fetch failed");
                }
            }
            if !work.fetch.is_empty() {
                continue;
            }
            let wait = Duration::from_millis(work.next_poll_at.saturating_sub(now()).max(1));
            tokio::select! {
                () = self.inner.wake.notified() => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    async fn run_feed(&self) {
        let mut backoff = Duration::from_millis(250);
        loop {
            match self.follow_feed().await {
                Ok(()) => backoff = Duration::from_millis(250),
                Err(error) => tracing::warn!(%error, "change feed disconnected"),
            }
            self.core().on_feed_lost();
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(10));
        }
    }

    /// Follows the feed until it ends or fails.
    async fn follow_feed(&self) -> Result<(), Error> {
        let mut request = self
            .inner
            .http
            .get(format!("{}/v1/events", self.inner.config.relying_url))
            .bearer_auth(self.bearer().await?);
        if let Some(cursor) = self.core().feed_cursor() {
            request = request.header("last-event-id", cursor.to_string());
        }
        let response = checked(request.send().await?).await?;
        self.core().on_feed_connected(now());
        self.inner.wake.notify_waiters();
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        while let Some(chunk) = stream.next().await {
            buffer.push_str(&String::from_utf8_lossy(&chunk?));
            while let Some(end) = buffer.find("\n\n") {
                let block: String = buffer.drain(..end + 2).collect();
                let data = block
                    .lines()
                    .filter_map(|line| line.strip_prefix("data:"))
                    .map(str::trim)
                    .collect::<String>();
                if data.is_empty() {
                    // A heartbeat comment.
                    self.core().on_feed_activity(now());
                    continue;
                }
                let event: FeedEvent = serde_json::from_str(&data).map_err(|e| Error::Status {
                    status: 0,
                    body: format!("malformed feed event: {e}"),
                })?;
                self.core()
                    .on_feed_event(&event, now())
                    .map_err(|e| Error::Status {
                        status: 0,
                        body: format!("malformed feed event: {e}"),
                    })?;
                self.inner.wake.notify_waiters();
            }
        }
        Ok(())
    }

    /// Whether decisions are currently made locally.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.core().is_trusted(now())
    }
}

fn entitlements_path(key: &Key) -> String {
    match key.tenant {
        Some(tenant) => format!("/v1/entitlements/{}/{tenant}", key.subject),
        None => format!("/v1/entitlements/{}", key.subject),
    }
}

async fn checked(response: reqwest::Response) -> Result<reqwest::Response, Error> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(Error::Status {
            status: response.status().as_u16(),
            body: response.text().await.unwrap_or_default(),
        })
    }
}
