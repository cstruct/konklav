//! Runtime configuration, loaded with ordna from a Styx file, a secrets Styx
//! file and `CONCLAVE__*` environment variables, in that order of precedence.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use conclave_store::ConnectOptions;
use ordna_core::{
    ConfigBuilder, ConfigContexts, ConfigLoadError, ConfigPath, SourceFieldPath, config_contexts,
    config_tree,
};
use ordna_source_env::{EnvSource, EnvSourceError, EnvVarDetail};
use ordna_source_file::{FileSourceError, FileValueDetail};
use ordna_source_styx::{DeserializeError, styx_file};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// The prefix of environment variables that override config values, as in
/// `CONCLAVE__LISTEN__SUBJECT=0.0.0.0:8080`.
pub const ENV_PREFIX: &str = "CONCLAVE";

// Each entrypoint loads only the contexts it needs, but every source is
// checked against the fields of all of them: a key meant for another
// entrypoint is accepted, a typo is still an unknown key.

config_tree! {
    /// Where each surface listens. Surfaces configured with the same address
    /// share one listener.
    #[derive(Debug, Clone, PartialEq)]
    pub struct ListenConfig {
        pub listen: pub struct Listen {
            pub subject: SocketAddr,
            pub relying: SocketAddr,
            pub control: SocketAddr,
        },
    }
}

config_tree! {
    #[derive(Debug, Clone, PartialEq)]
    pub struct DatabaseConfig {
        pub database: pub struct Database {
            pub host: String,
            pub port: u16,
            pub name: String,
            pub user: String,
            #[config(secret)]
            pub password: String,
            #[facet(default = 10)]
            pub max_connections: u32,
        },
    }
}

config_tree! {
    #[derive(Debug, Clone, PartialEq)]
    pub struct LogConfig {
        pub log: Option<pub struct Log {
            /// A `tracing_subscriber` filter directive, such as `info` or
            /// `conclave_server=debug,info`.
            pub filter: Option<String>,
        }>,
    }
}

config_tree! {
    /// Access-token issuance, session lifetimes and response pacing.
    #[derive(Debug, Clone, PartialEq)]
    pub struct TokensConfig {
        pub tokens: pub struct Tokens {
            /// The `iss` claim, usually Conclave's public base URL.
            pub issuer: String,
            /// The `aud` claim relying systems expect.
            pub audience: String,
            #[facet(default = 900)]
            pub access_ttl_seconds: u32,
            /// Absolute session lifetime; refreshing never extends it.
            #[facet(default = 2_592_000)]
            pub session_lifetime_seconds: u32,
            /// PKCS#8 PEM file with the Ed25519 key that signs new tokens.
            pub signing_key_file: String,
            /// More PEM files whose public keys are published without
            /// signing, such as the next key ahead of a rotation.
            #[facet(default)]
            pub published_key_files: Vec<String>,
        },
        /// Conclave as an OpenID provider. A section of its own, loaded with
        /// tokens (contexts are limited in number). Without it, the
        /// `/v1/oauth2/*` endpoints and discovery answer 404.
        pub oidc_provider: Option<pub struct OidcProvider {
            /// PKCS#8 PEM file with the P-256 key that signs `ES256` ID
            /// tokens.
            pub id_token_key_file: String,
            /// Where authorization requests send people to sign in, unless
            /// the client registered its own login URL.
            pub login_url: String,
            /// Defaults to `{issuer}/.well-known/jwks.json`.
            pub jwks_uri: Option<String>,
        }>,
        /// How long authentication endpoints take at least, so their
        /// response times don't reveal which identifiers exist. A section
        /// of its own, loaded with tokens (contexts are limited in number).
        pub pacing: Option<pub struct Pacing {
            #[facet(default = 1500)]
            pub floor_ms: u32,
            /// Each response waits the floor plus or minus up to this much.
            #[facet(default = 250)]
            pub jitter_ms: u32,
        }>,
    }
}

config_tree! {
    /// Browser clients, and the identity providers they can sign in
    /// through. Without `browser`, browser logins are refused.
    #[derive(Debug, Clone, PartialEq)]
    pub struct BrowserConfig {
        pub browser: Option<pub struct Browser {
            /// Origins allowed to use cookie-based endpoints, such as
            /// `https://app.example`.
            pub allowed_origins: Vec<String>,
            /// Set to `false` only for local development over plain HTTP.
            #[facet(default = true)]
            pub secure_cookies: bool,
        }>,
        /// OpenID providers browser clients can sign in through. A section
        /// of its own, loaded with `browser` (contexts are limited in
        /// number).
        #[facet(default)]
        pub identity_providers: Vec<pub struct IdentityProvider {
            /// Used in URLs and credential identifiers; lowercase.
            pub id: String,
            /// The provider's issuer; endpoints and keys come from its
            /// discovery document.
            pub issuer: String,
            pub client_id: String,
            /// This instance's `/v1/login/oidc/{id}/callback` URL, as
            /// registered at the provider.
            pub redirect_uri: String,
            /// Defaults to `openid email`.
            #[facet(default)]
            pub scopes: Vec<String>,
            /// Pages a login may return to; the first is the default.
            pub return_urls: Vec<String>,
            /// Provider `amr` or `acr` values credited as Conclave
            /// authentication methods.
            #[facet(default)]
            pub methods: Vec<pub struct MethodMapping {
                pub from: String,
                pub to: String,
            }>,
            /// Required `acr`, requested as `acr_values`.
            pub require_acr: Option<String>,
            /// Required authentication recency, requested as `max_age`.
            pub max_age_seconds: Option<u32>,
            /// Caps sessions started through this provider.
            pub session_lifetime_seconds: Option<u32>,
            /// What happens when an account nobody linked signs in: `link`
            /// (the default) refuses it, `create` creates a subject.
            pub provisioning: Option<String>,
            /// Email domains whose verified addresses may link an account to
            /// the subject with that login identifier. Off when empty.
            #[facet(default)]
            pub link_verified_email_domains: Vec<String>,
            /// Claim mapping: each rule that matches grants a global role, or
            /// a membership in a tenant with roles there.
            #[facet(default)]
            pub grants: Vec<pub struct ClaimGrant {
                /// The claim to test, such as `groups`.
                pub claim: String,
                /// Matches when the claim is this string.
                pub equals: Option<String>,
                /// Matches when the claim is a list holding this string.
                pub contains: Option<String>,
                pub global_role: Option<String>,
                /// A tenant id; the membership is created if missing.
                pub tenant: Option<String>,
                /// Role keys in `tenant`.
                #[facet(default)]
                pub roles: Vec<String>,
            }>,
        }>,
        /// Client secrets for `identity_providers`, by provider id.
        #[config(secret)]
        #[facet(default)]
        pub identity_provider_secrets: Vec<pub struct IdentityProviderSecret {
            pub provider: String,
            pub client_secret: String,
        }>,
    }
}

config_tree! {
    /// Control-plane access. Operators authenticate with access tokens and
    /// need `conclave:` capabilities. A bootstrap token, if configured, is
    /// accepted for everything: use it to create the first operator, then
    /// remove it.
    #[derive(Debug, Clone, PartialEq)]
    pub struct ControlConfig {
        pub control: Option<pub struct Control {
            #[config(secret)]
            pub bootstrap_token: Option<String>,
        }>,
    }
}

config_tree! {
    /// The change feed.
    #[derive(Debug, Clone, PartialEq)]
    pub struct FeedConfig {
        pub feed: Option<pub struct Feed {
            /// How long events stay in the outbox.
            #[facet(default = 168)]
            pub retention_hours: u32,
            /// How often streams poll when no notification arrives.
            #[facet(default = 2000)]
            pub poll_interval_ms: u32,
        }>,
    }
}

impl FeedConfig {
    #[must_use]
    pub fn retention(&self) -> chrono::Duration {
        chrono::Duration::hours(i64::from(
            self.feed.as_ref().map_or(168, |f| f.retention_hours),
        ))
    }

    #[must_use]
    pub fn poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(u64::from(
            self.feed.as_ref().map_or(2000, |f| f.poll_interval_ms),
        ))
    }
}

config_tree! {
    /// MFA secrets. TOTP seeds are encrypted with the first key; every key
    /// decrypts, so keys rotate by prepending a new one.
    #[derive(Debug, Clone, PartialEq)]
    pub struct MfaConfig {
        pub mfa: Option<pub struct Mfa {
            #[config(secret)]
            pub totp_keys: Vec<pub struct TotpKey {
                pub id: String,
                /// 32 bytes, base64.
                pub key: String,
            }>,
        }>,
    }
}

impl TokensConfig {
    #[must_use]
    pub fn pacing_floor(&self) -> std::time::Duration {
        std::time::Duration::from_millis(u64::from(
            self.pacing.as_ref().map_or(1500, |p| p.floor_ms),
        ))
    }

    #[must_use]
    pub fn pacing_jitter(&self) -> std::time::Duration {
        std::time::Duration::from_millis(u64::from(
            self.pacing.as_ref().map_or(250, |p| p.jitter_ms),
        ))
    }
}

config_contexts!(
    pub ServerContexts = [
        ListenConfig,
        DatabaseConfig,
        LogConfig,
        TokensConfig,
        BrowserConfig,
        ControlConfig,
        FeedConfig,
        MfaConfig,
    ]
);

/// The contexts `serve` needs, which is everything.
pub type ServeContexts = (
    ListenConfig,
    DatabaseConfig,
    LogConfig,
    TokensConfig,
    BrowserConfig,
    ControlConfig,
    FeedConfig,
    MfaConfig,
);

/// The contexts `migrate` needs: no listeners.
pub type MigrateContexts = (DatabaseConfig, LogConfig);

impl Database {
    /// Builds the libpq connection URL, escaping user and password.
    #[must_use]
    pub fn connect_options(&self) -> ConnectOptions {
        // Everything outside RFC 3986 "unreserved" is escaped in userinfo.
        const USERINFO: &AsciiSet = &NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'.')
            .remove(b'_')
            .remove(b'~');
        let user = utf8_percent_encode(&self.user, USERINFO);
        let password = utf8_percent_encode(&self.password, USERINFO);
        let name = utf8_percent_encode(&self.name, USERINFO);
        ConnectOptions {
            url: format!(
                "postgres://{user}:{password}@{host}:{port}/{name}",
                host = self.host,
                port = self.port
            ),
            max_connections: self.max_connections as usize,
        }
    }
}

impl ControlConfig {
    #[must_use]
    pub fn bootstrap_token(&self) -> Option<String> {
        self.control
            .as_ref()
            .and_then(|c| c.bootstrap_token.clone())
    }
}

impl LogConfig {
    #[must_use]
    pub fn filter(&self) -> Option<&str> {
        self.log.as_ref().and_then(|log| log.filter.as_deref())
    }
}

/// Where a config value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Env { var: String, path: ConfigPath },
    File { file: PathBuf, path: ConfigPath },
}

impl SourceFieldPath for Origin {
    fn field_path(&self) -> &ConfigPath {
        match self {
            Origin::Env { path, .. } | Origin::File { path, .. } => path,
        }
    }

    fn source_kind(&self) -> &'static str {
        match self {
            Origin::Env { .. } => "env",
            Origin::File { .. } => "file",
        }
    }
}

#[derive(Debug)]
pub enum SourceError {
    Env(EnvSourceError),
    File(FileSourceError<DeserializeError>),
}

/// Configuration could not be loaded. Displays every problem found, one per
/// line.
#[derive(Debug)]
pub struct ConfigError(Box<ConfigLoadError<SourceError>>);

impl ConfigError {
    #[must_use]
    pub fn inner(&self) -> &ConfigLoadError<SourceError> {
        &self.0
    }
}

impl fmt::Display for ConfigError {
    // r[impl platform.config.report-all-errors]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source_name = |meta: &ordna_core::SourceMeta| {
            meta.name.clone().unwrap_or_else(|| meta.kind.to_string())
        };
        match self.0.as_ref() {
            ConfigLoadError::Source(error) => write!(
                f,
                "could not read config source {}: {:?}",
                source_name(&error.source),
                error.error
            ),
            ConfigLoadError::Violations(violations) => {
                writeln!(f, "invalid configuration:")?;
                for issue in violations.unknown_paths() {
                    writeln!(
                        f,
                        "  {}: unknown key (in {})",
                        issue.path,
                        source_name(&issue.source)
                    )?;
                }
                for issue in violations.layer_mismatches() {
                    writeln!(
                        f,
                        "  {}: is a {} value and cannot be set in {}",
                        issue.path,
                        issue.field_layer,
                        source_name(&issue.source)
                    )?;
                }
                for issue in violations.conflicts() {
                    writeln!(
                        f,
                        "  {}: conflicting values in {}",
                        issue.path,
                        source_name(&issue.source)
                    )?;
                }
                for issue in violations.missing_fields() {
                    writeln!(f, "  {}: missing", issue.path)?;
                }
                for issue in violations.decode_errors() {
                    writeln!(f, "  {}", issue.message)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Loads the contexts `X` from, in order of increasing precedence: the public
/// `config` file, the `secrets` file, and `env`.
///
/// Secret values are only accepted from the secrets file, and the secrets
/// file only accepts secret values.
// r[impl platform.config.layered]
// r[impl platform.config.secrets-separate]
pub fn load<X: ConfigContexts<ServerContexts>>(
    config: &Path,
    secrets: &Path,
    env: EnvSource,
) -> Result<X, ConfigError> {
    let file = || {
        ServerContexts::register_source(SourceError::File, |path, detail: FileValueDetail| {
            Origin::File {
                file: detail.file,
                path,
            }
        })
    };
    let env_registration =
        ServerContexts::register_source(SourceError::Env, |path, detail: EnvVarDetail| {
            Origin::Env {
                var: detail.name,
                path,
            }
        });

    ConfigBuilder::<ServerContexts, _, _>::new()
        .source_named("config file", file(), styx_file(config))
        .source_named("secrets file", file(), styx_file(secrets).secrets())
        .source_named("environment", env_registration, env)
        .load_contexts()
        .map_err(|error| ConfigError(Box::new(error)))
}

/// The environment source for the process environment.
#[must_use]
pub fn process_env() -> EnvSource {
    EnvSource::with_prefix(ENV_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database(user: &str, password: &str) -> Database {
        Database {
            host: "db.internal".into(),
            port: 5432,
            name: "conclave".into(),
            user: user.into(),
            password: password.into(),
            max_connections: 3,
        }
    }

    #[test]
    fn builds_a_connection_url() {
        let options = database("conclave", "secret").connect_options();
        assert_eq!(
            options.url,
            "postgres://conclave:secret@db.internal:5432/conclave"
        );
        assert_eq!(options.max_connections, 3);
    }

    #[test]
    fn escapes_reserved_characters_in_credentials() {
        let options = database("svc@acme", "p@ss:w/rd?#").connect_options();
        assert_eq!(
            options.url,
            "postgres://svc%40acme:p%40ss%3Aw%2Frd%3F%23@db.internal:5432/conclave"
        );
    }
}
