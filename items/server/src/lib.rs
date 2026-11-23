//! The Konklav server: one binary serving the subject-facing, relying and
//! control-plane surfaces.

pub mod batch_api;
pub mod bootstrap;
mod capabilities;
pub mod claim_mapping;
pub mod claims_hook;
mod client_address;
pub mod config;
mod control_api;
mod control_authz;
mod cookies;
mod cors;
mod db;
mod dpop;
pub mod error;
mod explain_api;
pub mod export;
pub mod federation;
mod federation_api;
pub mod feed;
mod flows;
pub mod health;
mod import;
mod import_api;
mod invites;
mod issue;
pub mod keys;
pub mod login_page;
pub mod metadata;
mod metadata_api;
pub mod oidc;
mod oidc_api;
mod oidc_clients_api;
pub mod openapi;
mod outbound;
pub mod pacing;
pub mod passkeys;
mod passkeys_api;
pub mod peering;
mod registered_scopes_api;
mod relying_api;
pub mod serve;
mod shares_api;
mod subject_api;
pub mod surface;
pub mod sweeper;
pub mod telemetry;
mod transport;

use std::sync::Arc;

use chrono::Duration;
use konklav_authn::PasswordHasher;
use konklav_store::Pool;
use konklav_token::Signer;

/// State shared by every handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
    pub auth: Arc<AuthContext>,
    pub feed: Arc<feed::FeedHub>,
}

/// Settings and keys for authentication, built once at startup.
pub struct AuthContext {
    pub issuer: String,
    pub audience: String,
    pub access_ttl: Duration,
    pub session_lifetime: Duration,
    pub hasher: PasswordHasher,
    /// Bounds concurrent password hashing; see [`AuthContext::hashing`].
    pub hashing_slots: HashingSlots,
    pub signer: Signer,
    pub browser: Option<BrowserSettings>,
    /// The bootstrap control-plane token, if configured.
    pub control_token: Option<String>,
    /// When the bootstrap token stops being accepted, if ever.
    pub control_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Encrypts TOTP seeds.
    pub secrets: konklav_authn::SecretBox,
    /// How long authentication endpoints take at least.
    pub pacing: pacing::Pacing,
    /// Identity providers browser clients can sign in through.
    pub identity_providers: federation::Providers,
    /// Konklav's OpenID provider role, when configured.
    pub oidc: Option<oidc::OpenIdProvider>,
    /// Passkey support, when configured.
    pub passkeys: Option<passkeys::Verifier>,
    /// The built-in login page, when configured.
    pub login_page: Option<login_page::LoginPage>,
    /// Reverse proxies trusted to report client addresses.
    pub trusted_proxies: Vec<std::net::IpAddr>,
    /// How large control-plane batches may be, and how long their
    /// idempotency keys are kept.
    pub batches: batch_api::BatchLimits,
    /// The largest an object's metadata may be, in bytes of compact JSON.
    pub metadata_limit: usize,
    /// Base URLs DPoP proofs to Konklav's own surfaces may name; the issuer
    /// when empty.
    pub dpop_urls: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct BrowserSettings {
    pub allowed_origins: Vec<String>,
    pub secure_cookies: bool,
    /// Whether browser sessions must be bound to a DPoP key.
    pub require_dpop: bool,
}

/// Bounds password hashing: how many jobs run at once, and how many more
/// may wait for a slot.
pub struct HashingSlots {
    running: Arc<tokio::sync::Semaphore>,
    /// One place per job that runs or waits.
    places: Arc<tokio::sync::Semaphore>,
}

impl HashingSlots {
    /// Jobs that may wait per job that may run. A waiting request holds
    /// little, so the queue only needs to be short enough to drain well
    /// within a request's time limit.
    const WAITING_PER_SLOT: usize = 32;

    /// At most `running` jobs at a time, with at most `waiting` more
    /// queued for a slot.
    #[must_use]
    pub fn new(running: usize, waiting: usize) -> Self {
        Self {
            running: Arc::new(tokio::sync::Semaphore::new(running)),
            places: Arc::new(tokio::sync::Semaphore::new(running.saturating_add(waiting))),
        }
    }
}

/// A place among the requests that run or wait for password hashing; see
/// [`AuthContext::hashing_place`].
#[must_use = "run the hashing, or drop the place to give it up"]
pub(crate) struct HashingPlace<'a> {
    auth: &'a AuthContext,
    place: tokio::sync::OwnedSemaphorePermit,
}

impl HashingPlace<'_> {
    /// Waits for a slot and runs `work` on the blocking pool. The slot is
    /// held until the work ends, even if the request is dropped first.
    pub(crate) async fn run<T: Send + 'static>(
        self,
        work: impl FnOnce(&PasswordHasher) -> T + Send + 'static,
    ) -> Result<T, error::ApiError> {
        let metrics = &telemetry::metrics::METRICS;
        let waiting = std::time::Instant::now();
        let slot = self
            .auth
            .hashing_slots
            .running
            .clone()
            .acquire_owned()
            .await
            .map_err(error::ApiError::internal)?;
        metrics
            .hashing_wait
            .record(telemetry::metrics::seconds(waiting.elapsed()), &[]);
        let hasher = self.auth.hasher.clone();
        let place = self.place;
        tokio::task::spawn_blocking(move || {
            metrics.hashing_busy.add(1, &[]);
            let done = work(&hasher);
            metrics.hashing_busy.add(-1, &[]);
            drop((slot, place));
            done
        })
        .await
        .map_err(error::ApiError::internal)
    }
}

impl AuthContext {
    /// One hashing slot per CPU, and a bounded queue for each.
    #[must_use]
    pub fn default_hashing_slots() -> HashingSlots {
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        HashingSlots::new(cpus, cpus.saturating_mul(HashingSlots::WAITING_PER_SLOT))
    }

    /// Takes a place among the requests that run or wait for password
    /// hashing, or refuses at once when they are all taken: without a bound
    /// on the queue, a burst of logins would pile up behind the slots until
    /// each timed out. Take the place before doing anything else for the
    /// request, so a refused one costs and records nothing.
    // r[impl authn.login.hashing-bound]
    pub(crate) fn hashing_place(&self) -> Result<HashingPlace<'_>, error::ApiError> {
        match self.hashing_slots.places.clone().try_acquire_owned() {
            Ok(place) => Ok(HashingPlace { auth: self, place }),
            Err(_) => Err(error::ApiError::new(
                error::ErrorCode::Overloaded,
                "too many logins in progress; try again shortly",
            )),
        }
    }

    /// Runs password hashing or verification on the blocking pool, at most
    /// one per CPU at a time. Without a bound, a burst of logins would queue
    /// unbounded CPU work and starve everything else; with it, the excess
    /// waits for a slot, and what the queue has no place for is refused.
    ///
    /// Don't hold a database connection across this: requests queued here
    /// would pin the pool's connections and starve unrelated endpoints.
    // r[impl authn.login.hashing-bound]
    pub(crate) async fn hashing<T: Send + 'static>(
        &self,
        work: impl FnOnce(&PasswordHasher) -> T + Send + 'static,
    ) -> Result<T, error::ApiError> {
        self.hashing_place()?.run(work).await
    }

    /// Builds the context from configuration and the already-loaded signer,
    /// with no MFA encryption keys (set `secrets` to add them).
    ///
    /// # Panics
    ///
    /// Never: an empty key set is always valid.
    #[must_use]
    pub fn new(
        tokens: &config::Tokens,
        browser: Option<&config::Browser>,
        control: &config::ControlConfig,
        signer: Signer,
    ) -> Self {
        Self {
            issuer: tokens.issuer.clone(),
            audience: tokens.audience.clone(),
            access_ttl: Duration::seconds(i64::from(tokens.access_ttl_seconds)),
            session_lifetime: Duration::seconds(i64::from(tokens.session_lifetime_seconds)),
            hasher: PasswordHasher::default(),
            hashing_slots: Self::default_hashing_slots(),
            signer,
            browser: browser.map(|browser| BrowserSettings {
                allowed_origins: browser.allowed_origins.clone(),
                secure_cookies: browser.secure_cookies,
                require_dpop: browser.require_dpop,
            }),
            control_token: control.bootstrap_token(),
            control_token_expires_at: None,
            secrets: konklav_authn::SecretBox::new([]).expect("an empty key set is valid"),
            pacing: pacing::Pacing::DEFAULT,
            identity_providers: federation::Providers::default(),
            oidc: None,
            passkeys: None,
            login_page: None,
            trusted_proxies: Vec::new(),
            batches: control.batches(),
            metadata_limit: control.metadata_limit(),
            dpop_urls: tokens.dpop_urls.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn context(slots: usize) -> AuthContext {
        let tokens = config::Tokens {
            issuer: "https://konklav.test".into(),
            audience: "test".into(),
            access_ttl_seconds: 900,
            session_lifetime_seconds: 3600,
            signing_key_file: String::new(),
            published_key_files: Vec::new(),
            dpop_urls: Vec::new(),
        };
        let signer = Signer::new(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        let mut auth = AuthContext::new(
            &tokens,
            None,
            &config::ControlConfig { control: None },
            signer,
        );
        auth.hashing_slots = HashingSlots::new(slots, 16);
        auth
    }

    // r[verify authn.login.hashing-bound]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hashing_runs_at_most_one_job_per_slot() {
        let auth = Arc::new(context(2));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let jobs = (0..8).map(|_| {
            let (auth, running, peak) = (auth.clone(), running.clone(), peak.clone());
            tokio::spawn(async move {
                auth.hashing(move |_| {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    running.fetch_sub(1, Ordering::SeqCst);
                })
                .await
                .unwrap();
            })
        });
        for job in futures_util::future::join_all(jobs).await {
            job.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    // r[verify authn.login.hashing-bound]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hashing_refuses_what_its_queue_has_no_place_for() {
        let mut auth = context(1);
        auth.hashing_slots = HashingSlots::new(1, 1);
        let auth = Arc::new(auth);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let running = {
            let auth = auth.clone();
            tokio::spawn(async move { auth.hashing(move |_| held.recv().ok()).await })
        };
        let waiting = {
            let auth = auth.clone();
            tokio::spawn(async move { auth.hashing(|_| ()).await })
        };
        // Both places are taken once the two jobs have started.
        while auth.hashing_slots.places.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        let refused = auth.hashing(|_| ()).await.unwrap_err();
        assert_eq!(refused.code, error::ErrorCode::Overloaded);

        release.send(()).unwrap();
        running.await.unwrap().unwrap();
        waiting.await.unwrap().unwrap();
        // The places come back with the work.
        while auth.hashing_slots.places.available_permits() < 2 {
            tokio::task::yield_now().await;
        }
        auth.hashing(|_| ()).await.unwrap();
    }

    // r[verify authn.login.hashing-bound]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_dropped_request_keeps_its_slot_until_its_hashing_ends() {
        let auth = Arc::new(context(1));
        let (release, held) = std::sync::mpsc::channel::<()>();
        let (started, running) = tokio::sync::oneshot::channel::<()>();
        let job = {
            let auth = auth.clone();
            tokio::spawn(async move {
                auth.hashing(move |_| {
                    started.send(()).ok();
                    held.recv().ok();
                })
                .await
            })
        };
        running.await.unwrap();
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
        assert_eq!(auth.hashing_slots.running.available_permits(), 0);
        release.send(()).unwrap();
        auth.hashing(|_| ()).await.unwrap();
    }
}
