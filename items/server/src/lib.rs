//! The Konklav server: one binary serving the subject-facing, relying and
//! control-plane surfaces.

pub mod bootstrap;
mod capabilities;
pub mod claim_mapping;
pub mod claims_hook;
mod client_address;
pub mod config;
mod control_api;
mod control_authz;
mod cookies;
pub mod error;
mod explain_api;
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
pub mod oidc;
mod oidc_api;
mod oidc_clients_api;
pub mod openapi;
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
    pub hashing_slots: tokio::sync::Semaphore,
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
    /// Reverse proxies trusted to report client addresses.
    pub trusted_proxies: Vec<std::net::IpAddr>,
}

#[derive(Clone, Debug)]
pub struct BrowserSettings {
    pub allowed_origins: Vec<String>,
    pub secure_cookies: bool,
}

impl AuthContext {
    /// One hashing slot per CPU.
    #[must_use]
    pub fn default_hashing_slots() -> tokio::sync::Semaphore {
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        tokio::sync::Semaphore::new(cpus)
    }

    /// Runs password hashing or verification on the blocking pool, at most
    /// one per CPU at a time. Without a bound, a burst of logins would queue
    /// unbounded CPU work and starve everything else; with it, the excess
    /// waits for a slot.
    // r[impl authn.login.hashing-bound]
    pub(crate) async fn hashing<T: Send + 'static>(
        &self,
        work: impl FnOnce(&PasswordHasher) -> T + Send + 'static,
    ) -> Result<T, error::ApiError> {
        let metrics = &telemetry::metrics::METRICS;
        let waiting = std::time::Instant::now();
        let _slot = self
            .hashing_slots
            .acquire()
            .await
            .map_err(error::ApiError::internal)?;
        metrics
            .hashing_wait
            .record(telemetry::metrics::seconds(waiting.elapsed()), &[]);
        metrics.hashing_busy.add(1, &[]);
        let hasher = self.hasher.clone();
        let done = tokio::task::spawn_blocking(move || work(&hasher)).await;
        metrics.hashing_busy.add(-1, &[]);
        done.map_err(error::ApiError::internal)
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
            }),
            control_token: control.bootstrap_token(),
            control_token_expires_at: None,
            secrets: konklav_authn::SecretBox::new([]).expect("an empty key set is valid"),
            pacing: pacing::Pacing::DEFAULT,
            identity_providers: federation::Providers::default(),
            oidc: None,
            passkeys: None,
            trusted_proxies: Vec::new(),
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
        };
        let signer = Signer::new(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        let mut auth = AuthContext::new(
            &tokens,
            None,
            &config::ControlConfig { control: None },
            signer,
        );
        auth.hashing_slots = tokio::sync::Semaphore::new(slots);
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
}
