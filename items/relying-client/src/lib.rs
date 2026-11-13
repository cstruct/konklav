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
//! - It accepts a request's presentation once
//!   ([`RelyingClient::accept_request`]), for a host that needs the verified
//!   claims before it can state the requirements, or decides more than once
//!   per request, and decides for it later, as often as the request needs
//!   ([`RelyingClient::decide_accepted`]), without checking its DPoP proof
//!   again, until it releases it ([`RelyingClient::release_accepted`]).
//! - It hands erasures to the relying system: [`RelyingClient::erasures`]
//!   yields each erased subject as the feed reports it, and says when some
//!   may have been missed; [`RelyingClient::erased_subjects`] reads the
//!   erased subjects from Konklav to catch up.
//!
//! [`rate_limit::RateLimit`] enforces rate limits, through Redis with the
//! `redis` feature and in memory always. [`pacing`] and [`fake_ids`] keep a
//! relying system's own endpoints from showing, through their timing or
//! their ids, whether a record exists.
//!
//! The decision rules live in `konklav-relying`; this crate only moves bytes.

pub mod fake_ids;
pub mod pacing;
pub mod rate_limit;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use konklav_authz::{Decision, DenyReason, EntitlementSet, Requirements};
use konklav_core::Cursor;
pub use konklav_core::feed::SubjectErased;
use konklav_core::feed::{FeedEvent, SessionChanged};
use konklav_relying::{
    Acceptance, Config, Key, Need, Outcome, PresentationId, Relying, ScopeRecord, Verification,
};
pub use konklav_relying::{ErasureNotice, Presented, RequestDescriptor, policy};
use konklav_token::{AccessClaims, JwkSet, TokenKind};
use serde::Deserialize;
use tokio::sync::{Notify, mpsc};

/// Where Konklav is and how to authenticate to it.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Base URL of the relying surface, such as `https://konklav:8081`.
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
    #[error("konklav answered {status}: {body}")]
    Status { status: u16, body: String },
    #[error("could not reach a decision")]
    Exhausted,
}

/// What verifying a request's presentation found.
#[derive(Clone, Debug, PartialEq)]
pub enum Verified<T> {
    /// The token verifies, its session is current and any proof is
    /// accepted.
    Valid(T),
    /// The token doesn't verify, or its session has ended or moved on.
    Invalid,
    /// Refused for the DPoP proof or the authorization scheme: answer with
    /// `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
    InvalidProof,
}

/// A request's presentation that [`RelyingClient::accept_request`]
/// accepted, for the decisions of its request with
/// [`RelyingClient::decide_accepted`], until it expires or
/// [`RelyingClient::release_accepted`] releases it.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedRequest {
    claims: AccessClaims,
    presentation: PresentationId,
    access_token: String,
}

impl AcceptedRequest {
    /// The verified token's claims.
    #[must_use]
    pub fn claims(&self) -> &AccessClaims {
        &self.claims
    }
}

/// Every token kind, for verifying a token through the check API whatever
/// its kind.
const EVERY_TOKEN_KIND: [TokenKind; 5] = [
    TokenKind::Partial,
    TokenKind::Identity,
    TokenKind::Tenant,
    TokenKind::ResetPassword,
    TokenKind::Invite,
];

/// `value` as one percent-encoded URL path segment: scope ids are opaque.
fn path_segment(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
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
    /// Where erasure notices go, once the host has asked for them.
    erasures: Mutex<Option<mpsc::UnboundedSender<ErasureNotice>>>,
}

/// A relying client. Cheap to clone; clones share caches.
#[derive(Clone)]
pub struct RelyingClient {
    inner: Arc<Inner>,
}

/// One page of `/v1/erased-subjects`.
#[derive(Deserialize)]
struct ErasedPage {
    subjects: Vec<SubjectErased>,
    next: Option<konklav_core::SubjectId>,
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
                erasures: Mutex::new(None),
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

    /// The erasure notices from now on: each subject Konklav erases, so the
    /// relying system can remove its own data about it, and
    /// [`ErasureNotice::Missed`] when erasures may have been missed and
    /// [`Self::erased_subjects`] should be read.
    ///
    /// Call this before [`Self::start`]: a client that starts following
    /// the feed says at once that it may have missed erasures while it
    /// wasn't running. The same erasure may arrive more than once. Notices
    /// wait in the receiver without bound and are lost with it, so a
    /// relying system that must not miss one keeps the time it has handled
    /// erasures up to in its own storage, and reads
    /// [`Self::erased_subjects`] from there when it starts and on
    /// [`ErasureNotice::Missed`]. Only the latest receiver gets notices.
    // r[impl relying.erasure.notify]
    // r[impl relying.erasure.reset]
    #[must_use]
    pub fn erasures(&self) -> mpsc::UnboundedReceiver<ErasureNotice> {
        let (sender, receiver) = mpsc::unbounded_channel();
        *self
            .inner
            .erasures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sender);
        receiver
    }

    fn hand_over(&self, notice: ErasureNotice) {
        let mut erasures = self
            .inner
            .erasures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(sender) = erasures.as_ref()
            && sender.send(notice).is_err()
        {
            // The host dropped its receiver.
            *erasures = None;
        }
    }

    /// Every subject Konklav erased at or after `since` (Unix seconds), or
    /// ever when `None`, in the order they were erased. Unlike the feed,
    /// this reaches back however long the relying system was away.
    pub async fn erased_subjects(&self, since: Option<i64>) -> Result<Vec<SubjectErased>, Error> {
        let mut erased = Vec::new();
        let mut after: Option<konklav_core::SubjectId> = None;
        loop {
            let path = format!(
                "/v1/erased-subjects?limit=1000{}{}",
                since
                    .map(|since| format!("&since={since}"))
                    .unwrap_or_default(),
                after
                    .map(|after| format!("&after={after}"))
                    .unwrap_or_default()
            );
            let page: ErasedPage = checked(self.get(&path).await?).await?.json().await?;
            erased.extend(page.subjects);
            match page.next {
                Some(next) => after = Some(next),
                None => return Ok(erased),
            }
        }
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

    /// Decides `requirements` for a bearer access token presented to the
    /// relying system. Fails closed: an error means deny. A
    /// sender-constrained token is denied: use
    /// [`RelyingClient::decide_request`].
    pub async fn decide(
        &self,
        token: &str,
        requirements: &Requirements,
    ) -> Result<Decision, Error> {
        self.decide_request(&Presented::bearer(token), requirements)
            .await
    }

    /// Decides `requirements` for a request's raw `Authorization` and
    /// `DPoP` headers and the public URL the client addressed, so
    /// sender-constrained tokens work too. Fails closed: an error means
    /// deny.
    // r[impl relying.decision.fail-closed]
    pub async fn decide_request(
        &self,
        presented: &Presented,
        requirements: &Requirements,
    ) -> Result<Decision, Error> {
        // The core checks any DPoP proof; the check API takes the token
        // alone.
        let token = presented.access_token().unwrap_or_default();
        self.decide_with(token, requirements, |core| {
            core.decide_presented(presented, requirements, now())
        })
        .await
    }

    /// Accepts a request's presentation: verifies the token, its session
    /// and any DPoP proof, once, and returns the verified claims with the
    /// presentation to decide for with [`RelyingClient::decide_accepted`],
    /// which doesn't check the proof again. Fails closed: an error means
    /// deny.
    // r[impl relying.verify.accepted-presentation]
    pub async fn accept_request(
        &self,
        presented: &Presented,
    ) -> Result<Verified<AcceptedRequest>, Error> {
        let token = presented.access_token().unwrap_or_default();
        for _ in 0..4 {
            let acceptance = self.core().accept_presented(presented, now());
            let (claims, presentation) = match acceptance {
                Acceptance::Accepted {
                    claims,
                    presentation,
                } => (*claims, presentation),
                Acceptance::Check { presentation } => match self.verify_centrally(token).await? {
                    Some(claims) => (claims, presentation),
                    None => return Ok(Verified::Invalid),
                },
                Acceptance::Invalid => return Ok(Verified::Invalid),
                Acceptance::InvalidProof => return Ok(Verified::InvalidProof),
                Acceptance::Need { needs } => {
                    self.fetch_all(&needs).await?;
                    continue;
                }
            };
            return Ok(Verified::Valid(AcceptedRequest {
                claims,
                presentation,
                access_token: token.to_owned(),
            }));
        }
        Err(Error::Exhausted)
    }

    /// Decides `requirements` for a request [`RelyingClient::accept_request`]
    /// accepted, as often as the request needs. Its token and session are
    /// checked each time; its proof isn't. A request released, or accepted
    /// too long ago, is denied as `invalid_token`. Fails closed: an error
    /// means deny.
    pub async fn decide_accepted(
        &self,
        accepted: &AcceptedRequest,
        requirements: &Requirements,
    ) -> Result<Decision, Error> {
        self.decide_with(&accepted.access_token, requirements, |core| {
            core.decide_accepted(accepted.presentation, requirements, now())
        })
        .await
    }

    /// Releases a request [`RelyingClient::accept_request`] accepted, once
    /// it is answered: it decides nothing more, and its room in the core is
    /// free for another.
    // r[impl relying.verify.accepted-presentation]
    pub fn release_accepted(&self, accepted: &AcceptedRequest) {
        self.core().release_accepted(accepted.presentation);
    }

    /// Verifies a request's token, its session and any DPoP proof, without
    /// deciding anything: for requests that need no decision, such as to
    /// public routes. Fails closed: an error means deny.
    pub async fn verify_request(
        &self,
        presented: &Presented,
    ) -> Result<Verified<AccessClaims>, Error> {
        for _ in 0..4 {
            let verification = self.core().verify_presented(presented, now());
            match verification {
                Verification::Verified { claims } => return Ok(Verified::Valid(*claims)),
                Verification::Invalid => return Ok(Verified::Invalid),
                Verification::InvalidProof => return Ok(Verified::InvalidProof),
                Verification::Need { needs } if needs.contains(&Need::Check) => {
                    let token = presented.access_token().unwrap_or_default();
                    return Ok(match self.verify_centrally(token).await? {
                        Some(claims) => Verified::Valid(claims),
                        None => Verified::Invalid,
                    });
                }
                Verification::Need { needs } => self.fetch_all(&needs).await?,
            }
        }
        Err(Error::Exhausted)
    }

    /// Asks the core with `ask` until it decides, fetching what it needs,
    /// or asks the check API for `token` when the core can't decide.
    async fn decide_with(
        &self,
        token: &str,
        requirements: &Requirements,
        mut ask: impl FnMut(&mut Relying) -> Outcome,
    ) -> Result<Decision, Error> {
        for _ in 0..4 {
            let outcome = ask(&mut self.core());
            let needs = match outcome {
                Outcome::Decided { decision } => return Ok(decision),
                Outcome::Need { needs } => needs,
            };
            if needs.contains(&Need::Check) {
                return self.check(token, requirements).await;
            }
            self.fetch_all(&needs).await?;
        }
        Err(Error::Exhausted)
    }

    async fn fetch_all(&self, needs: &[Need]) -> Result<(), Error> {
        let results =
            futures_util::future::join_all(needs.iter().map(|need| self.fetch(need))).await;
        results
            .into_iter()
            .find_map(Result::err)
            .map_or(Ok(()), Err)
    }

    /// Verifies `token` through the check API, for when the caches can't
    /// be trusted: its claims if the check API vouches for it.
    async fn verify_centrally(&self, token: &str) -> Result<Option<AccessClaims>, Error> {
        let any = Requirements {
            token_kinds: Some(EVERY_TOKEN_KIND.into_iter().collect()),
            ..Requirements::default()
        };
        let decision = self.check(token, &any).await?;
        if matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::InvalidToken | DenyReason::InvalidDpopProof
            }
        ) {
            return Ok(None);
        }
        // The check API vouched for the token; read its claims.
        Ok(konklav_token::decode_claims_unverified(token))
    }

    /// Asks Konklav's check API, for when local caches can't be trusted,
    /// for a token with one of the audiences this relying system accepts.
    // r[impl relying.verify.audiences]
    async fn check(&self, token: &str, requirements: &Requirements) -> Result<Decision, Error> {
        let url = format!("{}/v1/check", self.inner.config.relying_url);
        let body = serde_json::json!({
            "token": token,
            "requirements": requirements,
            "audiences": self.inner.config.core.audiences,
        });
        let response = self
            .inner
            .http
            .post(url)
            .bearer_auth(self.bearer().await?)
            .json(&body)
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
            Need::RegisteredScope { kind, id } => {
                let path = format!(
                    "/v1/registered-scopes/{}/{}",
                    path_segment(kind),
                    path_segment(id)
                );
                let response = self.get(&path).await?;
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    self.core().on_registered_scope_unknown(kind, id, now());
                } else {
                    let record: ScopeRecord = checked(response).await?.json().await?;
                    self.core().on_registered_scope(record, now());
                }
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
                let notice =
                    self.core()
                        .on_feed_event(&event, now())
                        .map_err(|e| Error::Status {
                            status: 0,
                            body: format!("malformed feed event: {e}"),
                        })?;
                if let Some(notice) = notice {
                    self.hand_over(notice);
                }
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
