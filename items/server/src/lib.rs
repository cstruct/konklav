//! The Conclave server: one binary serving the subject-facing, relying and
//! control-plane surfaces.

pub mod config;
mod control_api;
mod control_authz;
pub mod error;
pub mod health;
mod issue;
pub mod keys;
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
    /// The interim control-plane bearer token (until M6).
    pub control_token: String,
}

#[derive(Clone, Debug)]
pub struct BrowserSettings {
    pub allowed_origins: Vec<String>,
    pub secure_cookies: bool,
}

impl AuthContext {
    /// Builds the context from configuration and the already-loaded signer.
    #[must_use]
    pub fn new(
        tokens: &config::Tokens,
        browser: Option<&config::Browser>,
        control: &config::Control,
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
            control_token: control.control_token(),
        }
    }
}
