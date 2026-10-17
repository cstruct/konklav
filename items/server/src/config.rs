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
    /// Access-token issuance and session lifetimes.
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
    }
}

config_tree! {
    /// Browser clients. Without this section, browser logins are refused.
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
    }
}

config_tree! {
    /// Control-plane access. Until operator authorization arrives (M6), the
    /// control surface accepts one static bearer token.
    #[derive(Debug, Clone, PartialEq)]
    pub struct ControlConfig {
        pub control: pub struct Control {
            #[config(secret)]
            pub bootstrap_token: String,
        },
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

impl Control {
    #[must_use]
    pub fn control_token(&self) -> String {
        self.bootstrap_token.clone()
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
