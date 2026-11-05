//! Runtime configuration, loaded with ordna from a Styx file, a secrets Styx
//! file and `KONKLAV__*` environment variables, in that order of precedence.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use konklav_store::ConnectOptions;
use ordna_core::{
    ConfigBuilder, ConfigContexts, ConfigLoadError, ConfigPath, SourceFieldPath, config_contexts,
    config_tree,
};
use ordna_source_env::{EnvSource, EnvSourceError, EnvVarDetail};
use ordna_source_file::{FileSourceError, FileValueDetail};
use ordna_source_styx::{DeserializeError, styx_file};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// The prefix of environment variables that override config values, as in
/// `KONKLAV__LISTEN__SUBJECT=0.0.0.0:8080`.
pub const ENV_PREFIX: &str = "KONKLAV";

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
            /// Reverse proxies whose `X-Forwarded-For` is believed when
            /// working out a client's address for rate limiting.
            #[facet(default)]
            pub trusted_proxies: Vec<IpAddr>,
        },
        /// Bounds on what each listener accepts. A section of its own,
        /// loaded with `listen`.
        pub limits: Option<pub struct Limits {
            /// How long a request may take to be answered. A change-feed
            /// stream counts only until it starts.
            #[facet(default = 30)]
            pub request_timeout_seconds: u32,
            #[facet(default = 2_097_152)]
            pub max_body_bytes: u32,
            /// Requests served at once per listener; more are refused.
            #[facet(default = 1024)]
            pub max_concurrent_requests: u32,
        }>,
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
    /// Logs, and exporting traces, metrics and logs over OTLP. Exporting is
    /// off unless enabled per signal.
    #[derive(Debug, Clone, PartialEq)]
    pub struct TelemetryConfig {
        #[facet(default)]
        pub telemetry: pub struct Telemetry {
            /// The `service.name` resource attribute.
            #[facet(default = String::from("konklav"))]
            pub service_name: String,
            /// More resource attributes, such as `deployment.environment`. A
            /// list, since attribute names contain dots, which map keys can't.
            /// `OTEL_RESOURCE_ATTRIBUTES` is read as well.
            #[facet(default)]
            pub resource: Vec<pub struct ResourceAttribute {
                pub key: String,
                pub value: String,
            }>,
            // r[impl telemetry.endpoints]
            /// Where and how to export. Settings left out fall back to the
            /// standard `OTEL_EXPORTER_OTLP_*` environment variables.
            #[facet(default)]
            pub otlp: pub struct Otlp {
                /// The collector's base URL, such as `http://collector:4318`;
                /// over HTTP, the signal's path, such as `/v1/metrics`, is
                /// appended.
                pub endpoint: Option<String>,
                #[facet(default)]
                pub protocol: #[derive(Default)] #[facet(rename_all = "snake_case")] pub enum OtlpProtocol {
                    /// Protobuf over HTTP, conventionally on port 4318.
                    #[default]
                    HttpProtobuf,
                    /// gRPC, conventionally on port 4317.
                    Grpc,
                },
                /// Headers sent with every export, such as an API key.
                #[config(secret)]
                #[facet(default)]
                pub headers: HashMap<String, String>,
                /// How long an export may take.
                #[facet(default = 10)]
                pub timeout_seconds: u32,
            },
            #[facet(default)]
            pub metrics: pub struct MetricsExport {
                #[facet(default)]
                pub enabled: bool,
                /// The full URL to export metrics to, overriding
                /// `otlp.endpoint`.
                pub endpoint: Option<String>,
                #[facet(default = 30)]
                pub interval_seconds: u32,
            },
            #[facet(default)]
            pub traces: pub struct TracesExport {
                #[facet(default)]
                pub enabled: bool,
                /// The full URL to export traces to, overriding
                /// `otlp.endpoint`.
                pub endpoint: Option<String>,
                /// The share of traces to sample, from 0 to 1. Requests whose
                /// caller sampled them are traced either way.
                #[facet(default = 1.0)]
                pub sample_ratio: f64,
            },
            // r[impl telemetry.logs]
            /// Logging, to stderr and optionally exported.
            #[facet(default)]
            pub logs: pub struct Logs {
                /// What to log, as `tracing` filter directives such as `info`
                /// or `info,konklav_server=debug`. `RUST_LOG` overrides it.
                #[facet(default = String::from("info"))]
                pub level: String,
                #[facet(default)]
                pub format: #[derive(Default)] #[facet(rename_all = "snake_case")] pub enum LogFormat {
                    /// Human-readable lines.
                    #[default]
                    Text,
                    /// A JSON object per line, with the trace and span ids of
                    /// traced requests.
                    Json,
                },
                /// Whether to export logs over OTLP too.
                #[facet(default)]
                pub export: bool,
                /// The full URL to export logs to, overriding
                /// `otlp.endpoint`.
                pub endpoint: Option<String>,
            },
        },
    }
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            service_name: "konklav".into(),
            resource: Vec::new(),
            otlp: Otlp::default(),
            metrics: MetricsExport::default(),
            traces: TracesExport::default(),
            logs: Logs::default(),
        }
    }
}

impl Default for Otlp {
    fn default() -> Self {
        Self {
            endpoint: None,
            protocol: OtlpProtocol::default(),
            headers: HashMap::new(),
            timeout_seconds: 10,
        }
    }
}

impl Default for MetricsExport {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            interval_seconds: 30,
        }
    }
}

impl Default for TracesExport {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            sample_ratio: 1.0,
        }
    }
}

impl Default for Logs {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::default(),
            export: false,
            endpoint: None,
        }
    }
}

impl Telemetry {
    /// The same logging, with nothing exported: for commands that run once.
    #[must_use]
    pub fn logs_only(&self) -> Self {
        Self {
            metrics: MetricsExport::default(),
            traces: TracesExport::default(),
            logs: Logs {
                export: false,
                ..self.logs.clone()
            },
            ..self.clone()
        }
    }
}

config_tree! {
    /// Access-token issuance, session lifetimes and response pacing.
    #[derive(Debug, Clone, PartialEq)]
    pub struct TokensConfig {
        pub tokens: pub struct Tokens {
            /// The `iss` claim, usually Konklav's public base URL.
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
            /// Base URLs at which clients address the subject-facing and
            /// control-plane surfaces, for the `htu` of DPoP proofs: a
            /// proof must name one of them followed by the request's path.
            /// List each prefix a reverse proxy mounts a surface under,
            /// such as `https://admin.example/control`. Defaults to the
            /// issuer and each of `browser.allowed_origins`, with and
            /// without the console's `/control` prefix.
            #[facet(default)]
            pub dpop_urls: Vec<String>,
        },
        /// Konklav as an OpenID provider. A section of its own, loaded with
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
            /// PKCS#8 PEM file with an RSA key of at least 2048 bits that
            /// signs `RS256` ID tokens. OpenID Connect requires providers to
            /// offer RS256; without this key, clients can't be registered
            /// for it.
            pub rsa_key_file: Option<String>,
            /// How old a DPoP proof may be, in seconds.
            #[facet(default = 60)]
            pub dpop_max_age_seconds: u32,
            /// Which clients must send a DPoP proof with every grant, on
            /// top of those registered with `require_dpop`.
            #[facet(default)]
            pub require_dpop: #[derive(Default, Copy, Eq)] #[facet(rename_all = "snake_case")] pub enum DpopRequirement {
                /// Only clients registered with `require_dpop`.
                #[default]
                None,
                /// Every public client: the browser and native apps that
                /// have no other proof of who they are.
                PublicClients,
                /// Every client.
                All,
            },
            /// A relying system's endpoint that userinfo asks for profile
            /// claims Konklav doesn't hold, such as `name`.
            pub claims_hook: Option<pub struct ClaimsHook {
                /// Where to `POST` the signed claims request.
                pub url: String,
                /// The scopes the hook serves, each with its claims, such
                /// as `profile (name given_name family_name)`.
                pub scopes: HashMap<String, Vec<String>>,
                #[facet(default = 1500)]
                pub timeout_ms: u32,
                /// What userinfo does when the hook fails.
                #[facet(default)]
                pub on_failure: #[derive(Default)] #[facet(rename_all = "snake_case")] pub enum ClaimsHookFailure {
                    /// Serve userinfo without the hook's claims.
                    #[default]
                    Omit,
                    /// Refuse userinfo with 503.
                    Fail,
                },
                /// How long answers are cached in memory; 0 turns caching
                /// off. An answer's `Cache-Control` can only shorten it.
                #[facet(default)]
                pub cache_ttl_seconds: u32,
                /// The most answers cached at once.
                #[facet(default = 10000)]
                pub cache_entries: u32,
            }>,
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
            /// Refuse browser logins and federated sign-ins that bring no
            /// DPoP key, so every browser session is bound.
            #[facet(default)]
            pub require_dpop: bool,
        }>,
        /// Passkey login and registration. A section of its own, loaded with
        /// `browser`. Without it, the passkey endpoints answer 404.
        pub passkeys: Option<pub struct Passkeys {
            /// The relying party ID: the domain passkeys are scoped to, such
            /// as `example.com`. WebAuthn does not allow IP addresses.
            pub rp_id: String,
            /// The name browsers show when a passkey is created.
            pub rp_name: String,
            /// Origins whose pages may use passkeys; each must be the relying
            /// party ID or a subdomain of it. Defaults to
            /// `browser.allowed_origins`.
            #[facet(default)]
            pub origins: Vec<String>,
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
            /// Provider `amr` or `acr` values credited as Konklav
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
            /// MFA factors a subject must prove here after signing in
            /// through this provider, as for its other credentials. `0`
            /// trusts the provider's authentication alone. It has no
            /// default, so the choice is deliberate.
            pub local_mfa_factors: u16,
            /// A JWKS file with the provider's signing keys, used instead of
            /// the keys its discovery document names.
            pub pinned_jwks_file: Option<String>,
            /// Follow the provider's peer feed (a Konklav upstream) to end
            /// sessions of subjects it disables and re-apply claim mapping
            /// when their claims change.
            #[facet(default)]
            pub peering: bool,
            /// Accept the provider's tokens for local service principals
            /// with the JWT bearer grant.
            #[facet(default)]
            pub workloads: bool,
            /// Email domains whose verified addresses may link an account to
            /// the subject with that login identifier. Off when empty.
            #[facet(default)]
            pub link_verified_email_domains: Vec<String>,
            /// Claims the provider reports that Konklav passes on to its own
            /// OIDC clients, by the scope they are served under, such as
            /// `profile (name locale)`. They are kept only while the session
            /// lasts.
            #[facet(default)]
            pub pass_claims: HashMap<String, Vec<String>>,
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
    /// need `konklav:` capabilities. A bootstrap token, if configured, is
    /// accepted for everything: use it to create the first operator, then
    /// remove it.
    #[derive(Debug, Clone, PartialEq)]
    pub struct ControlConfig {
        pub control: Option<pub struct Control {
            /// At least [`MIN_BOOTSTRAP_TOKEN_CHARS`] characters.
            #[config(secret)]
            pub bootstrap_token: Option<String>,
            /// When the bootstrap token stops working, as RFC 3339, such as
            /// `2026-11-01T00:00:00Z`.
            pub bootstrap_token_expires_at: Option<String>,
            /// Operations a batch may hold.
            #[facet(default = 100)]
            pub batch_max_operations: u32,
            /// How long a batch's idempotency key is remembered unless the
            /// batch asks for longer.
            #[facet(default = 600)]
            pub batch_key_seconds: u32,
            /// The longest a batch may ask for its key to be remembered.
            #[facet(default = 3600)]
            pub batch_key_max_seconds: u32,
        }>,
    }
}

config_tree! {
    /// The change feed, and how long other rows are kept.
    #[derive(Debug, Clone, PartialEq)]
    pub struct FeedConfig {
        pub feed: Option<pub struct Feed {
            /// How long events stay in the outbox.
            #[facet(default = 168)]
            pub retention_hours: u32,
            /// How often streams poll when no notification arrives.
            #[facet(default = 2000)]
            pub poll_interval_ms: u32,
            /// Streams open at once; more are refused as `OVERLOADED`.
            #[facet(default = 1000)]
            pub max_streams: u32,
        }>,
        // r[impl retention.sessions]
        /// What the sweeper deletes, and how often it runs.
        pub retention: Option<pub struct Retention {
            /// Days a session is kept after it expired or was revoked.
            #[facet(default = 30)]
            pub sessions_days: u32,
            /// How often the sweeper runs.
            #[facet(default = 300)]
            pub sweep_interval_seconds: u32,
            /// The most rows one delete removes, so no sweep holds locks long.
            #[facet(default = 1000)]
            pub batch_size: u32,
        }>,
        // r[impl history.config]
        /// Versions of the rows authorization reads, kept so decisions can
        /// be explained as of a past time. Every instance on a database
        /// must agree.
        pub history: Option<pub struct History {
            /// Off by default. Turning it off discards what was recorded.
            #[facet(default)]
            pub enabled: bool,
            /// Days a version is kept after it stopped being current.
            #[facet(default = 90)]
            pub retention_days: u32,
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
    pub fn max_streams(&self) -> usize {
        self.feed
            .as_ref()
            .map_or(crate::feed::FeedHub::DEFAULT_MAX_STREAMS, |f| {
                usize::try_from(f.max_streams).unwrap_or(usize::MAX)
            })
    }

    /// How long history keeps a version after it stopped being current, or
    /// `None` when history is off.
    #[must_use]
    pub fn history_retention(&self) -> Option<chrono::Duration> {
        self.history
            .as_ref()
            .filter(|history| history.enabled)
            .map(|history| chrono::Duration::days(i64::from(history.retention_days.max(1))))
    }

    /// What the sweeper keeps, with the change feed's retention.
    #[must_use]
    pub fn sweeper(&self) -> crate::sweeper::Settings {
        let retention = self.retention.as_ref();
        crate::sweeper::Settings {
            sessions: chrono::Duration::days(i64::from(retention.map_or(30, |r| r.sessions_days))),
            events: self.retention(),
            interval: std::time::Duration::from_secs(u64::from(
                retention.map_or(300, |r| r.sweep_interval_seconds).max(1),
            )),
            batch: i64::from(retention.map_or(1000, |r| r.batch_size).max(1)),
        }
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
        TelemetryConfig,
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
    TelemetryConfig,
    TokensConfig,
    BrowserConfig,
    ControlConfig,
    FeedConfig,
    MfaConfig,
);

/// The contexts `migrate` needs: no listeners.
pub type MigrateContexts = (DatabaseConfig, TelemetryConfig);

/// The contexts `bootstrap` needs: the database, and the MFA keys that
/// imported TOTP seeds are encrypted with.
pub type BootstrapContexts = (DatabaseConfig, TelemetryConfig, MfaConfig);

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

/// The shortest bootstrap token accepted, so it can't be guessed.
pub const MIN_BOOTSTRAP_TOKEN_CHARS: usize = 32;

impl ControlConfig {
    /// The batch limits, the defaults when `[control]` is absent.
    #[must_use]
    pub fn batches(&self) -> crate::batch_api::BatchLimits {
        self.control
            .as_ref()
            .map_or(crate::batch_api::BatchLimits::DEFAULT, |c| {
                crate::batch_api::BatchLimits {
                    max_operations: usize::try_from(c.batch_max_operations).unwrap_or(usize::MAX),
                    key_lifetime: std::time::Duration::from_secs(u64::from(c.batch_key_seconds)),
                    max_key_lifetime: std::time::Duration::from_secs(u64::from(
                        c.batch_key_max_seconds,
                    )),
                }
            })
    }

    #[must_use]
    pub fn bootstrap_token(&self) -> Option<String> {
        self.control
            .as_ref()
            .and_then(|c| c.bootstrap_token.clone())
    }

    /// Checks the bootstrap token and returns when it expires, if it does.
    // r[impl platform.config.bootstrap-token]
    pub fn bootstrap_expiry(&self) -> Result<Option<chrono::DateTime<chrono::Utc>>, String> {
        let Some(control) = &self.control else {
            return Ok(None);
        };
        if let Some(token) = &control.bootstrap_token
            && token.trim().chars().count() < MIN_BOOTSTRAP_TOKEN_CHARS
        {
            return Err(format!(
                "control.bootstrap_token needs at least {MIN_BOOTSTRAP_TOKEN_CHARS} characters"
            ));
        }
        control
            .bootstrap_token_expires_at
            .as_deref()
            .map(|at| {
                chrono::DateTime::parse_from_rfc3339(at)
                    .map(|at| at.to_utc())
                    .map_err(|error| {
                        format!("control.bootstrap_token_expires_at is not RFC 3339: {error}")
                    })
            })
            .transpose()
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
            name: "konklav".into(),
            user: user.into(),
            password: password.into(),
            max_connections: 3,
        }
    }

    #[test]
    fn builds_a_connection_url() {
        let options = database("konklav", "secret").connect_options();
        assert_eq!(
            options.url,
            "postgres://konklav:secret@db.internal:5432/konklav"
        );
        assert_eq!(options.max_connections, 3);
    }

    #[test]
    fn escapes_reserved_characters_in_credentials() {
        let options = database("svc@acme", "p@ss:w/rd?#").connect_options();
        assert_eq!(
            options.url,
            "postgres://svc%40acme:p%40ss%3Aw%2Frd%3F%23@db.internal:5432/konklav"
        );
    }
}
