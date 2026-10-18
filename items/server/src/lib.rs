//! The Conclave server: one binary serving the subject-facing, relying and
//! control-plane surfaces.

mod capabilities;
pub mod claim_mapping;
pub mod config;
mod control_api;
mod control_authz;
pub mod error;
pub mod federation;
mod federation_api;
pub mod feed;
mod flows;
pub mod health;
mod import_api;
mod invites;
mod issue;
pub mod keys;
pub mod oidc;
mod oidc_api;
mod oidc_clients_api;
pub mod pacing;
mod relying_api;
pub mod serve;
mod subject_api;
pub mod surface;

use std::sync::Arc;

use chrono::Duration;
use conclave_authn::PasswordHasher;
use conclave_store::Pool;
use conclave_token::Signer;

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
    pub signer: Signer,
    pub browser: Option<BrowserSettings>,
    /// The bootstrap control-plane token, if configured.
    pub control_token: Option<String>,
    /// Encrypts TOTP seeds.
    pub secrets: conclave_authn::SecretBox,
    /// How long authentication endpoints take at least.
    pub pacing: pacing::Pacing,
    /// Identity providers browser clients can sign in through.
    pub identity_providers: federation::Providers,
    /// Conclave's OpenID provider role, when configured.
    pub oidc: Option<oidc::OpenIdProvider>,
}

#[derive(Clone, Debug)]
pub struct BrowserSettings {
    pub allowed_origins: Vec<String>,
    pub secure_cookies: bool,
}

impl AuthContext {
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
            signer,
            browser: browser.map(|browser| BrowserSettings {
                allowed_origins: browser.allowed_origins.clone(),
                secure_cookies: browser.secure_cookies,
            }),
            control_token: control.bootstrap_token(),
            secrets: conclave_authn::SecretBox::new([]).expect("an empty key set is valid"),
            pacing: pacing::Pacing::DEFAULT,
            identity_providers: federation::Providers::default(),
            oidc: None,
        }
    }
}
