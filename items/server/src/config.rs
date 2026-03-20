use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use facet::Facet;
use serde::Deserialize;

type DynError = Box<dyn std::error::Error + Send + Sync>;

const DEFAULT_CONFIG_PATH: &str = "config/server.conf.styx";
const DEFAULT_SECRETS_PATH: &str = "config/server.secrets.styx";

#[derive(Clone, Debug)]
pub struct LoadedConfig {
    pub config: AppConfig,
    pub config_dir: PathBuf,
    pub managed_dir: PathBuf,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
pub struct AppConfig {
    pub control_plane: ListenerConfig,
    pub subject: ListenerConfig,
    pub relying: ListenerConfig,
    pub bootstrap: BootstrapConfig,
    pub jwt: JwtConfig,
    pub feldera: FelderaConfig,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
pub struct ListenerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
pub struct BootstrapConfig {
    pub subject: String,
    pub token: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
pub struct JwtConfig {
    pub issuer: String,
    pub default_audience: String,
    pub signing_private_key_file: PathBuf,
    pub ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
pub struct FelderaConfig {
    pub enabled: bool,
    pub base_url: String,
    pub pipeline_prefix: String,
    pub readiness_probe: bool,
    pub api_key: Option<String>,
    pub compile_profile: String,
    pub auto_start: bool,
    pub start_initial: String,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublicAppConfig {
    control_plane: ListenerConfig,
    subject: ListenerConfig,
    relying: ListenerConfig,
    bootstrap: PublicBootstrapConfig,
    jwt: PublicJwtConfig,
    feldera: PublicFelderaConfig,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublicBootstrapConfig {
    subject: String,
    display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublicJwtConfig {
    issuer: String,
    default_audience: String,
    signing_private_key_file: PathBuf,
    ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublicFelderaConfig {
    enabled: bool,
    base_url: String,
    pipeline_prefix: String,
    readiness_probe: bool,
    compile_profile: String,
    auto_start: bool,
    start_initial: String,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct SecretAppConfig {
    bootstrap: SecretBootstrapConfig,
    feldera: Option<SecretFelderaConfig>,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct SecretBootstrapConfig {
    token: String,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct SecretFelderaConfig {
    api_key: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            control_plane: ListenerConfig {
                host: "127.0.0.1".to_owned(),
                port: 8080,
            },
            subject: ListenerConfig {
                host: "127.0.0.1".to_owned(),
                port: 8081,
            },
            relying: ListenerConfig {
                host: "127.0.0.1".to_owned(),
                port: 8082,
            },
            bootstrap: BootstrapConfig {
                subject: "root-operator".to_owned(),
                token: "conclave-bootstrap-token".to_owned(),
                display_name: Some("Bootstrap root operator".to_owned()),
            },
            jwt: JwtConfig {
                issuer: "http://127.0.0.1:8082".to_owned(),
                default_audience: "conclave-dev".to_owned(),
                signing_private_key_file: PathBuf::from("server.signing-private-key.pem"),
                ttl_seconds: 900,
            },
            feldera: FelderaConfig {
                enabled: false,
                base_url: "http://127.0.0.1:8080".to_owned(),
                pipeline_prefix: "conclave".to_owned(),
                readiness_probe: true,
                api_key: None,
                compile_profile: "dev".to_owned(),
                auto_start: false,
                start_initial: "paused".to_owned(),
            },
        }
    }
}

impl AppConfig {
    // r[impl platform.server.bootstrap]
    // r[impl platform.server.multi-surface-runtime]
    // r[impl platform.server.split-config-files]
    // r[impl platform.server.strict-config-secrets-boundary]
    // r[impl platform.server.explicit-secrets-path]
    // r[impl platform.server.secret-file-only-values]
    pub fn load() -> Result<LoadedConfig, DynError> {
        Self::load_from(env::args_os())
    }

    fn load_from<I, T>(args: I) -> Result<LoadedConfig, DynError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let (overrides, override_sources) = StartupOverrides::parse(args)?;
        let config_path = overrides
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        let secrets_path = overrides
            .secrets
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SECRETS_PATH));
        let mut managed_dir = managed_config_dir(&config_path);
        let config_dir = config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let config_contents = read_required_file(&config_path, "config")?;
        let secrets_contents = read_required_file(&secrets_path, "secrets")?;
        let mut config = Self::from_split_styx(&config_contents, &secrets_contents)?;

        overrides.apply_to(&mut config, &mut managed_dir);

        Ok(LoadedConfig {
            config,
            config_dir,
            managed_dir,
            source: format_source(
                format!(
                    "config:{} + secrets:{}",
                    config_path.display(),
                    secrets_path.display()
                ),
                &override_sources,
            ),
        })
    }

    // r[impl platform.server.split-config-files]
    // r[impl platform.server.strict-config-secrets-boundary]
    // r[impl platform.server.secret-file-only-values]
    pub fn from_split_styx(config_input: &str, secrets_input: &str) -> Result<Self, DynError> {
        reject_forbidden_entries(
            config_input,
            "config",
            &["token", "signing_private_key", "api_key"],
        )?;
        reject_forbidden_entries(
            secrets_input,
            "secrets",
            &[
                "control_plane",
                "subject",
                "relying",
                "host",
                "port",
                "display_name",
                "issuer",
                "default_audience",
                "signing_private_key",
                "signing_private_key_file",
                "ttl_seconds",
                "enabled",
                "base_url",
                "pipeline_prefix",
                "readiness_probe",
                "compile_profile",
                "auto_start",
                "start_initial",
            ],
        )?;
        let config: PublicAppConfig = facet_styx::from_str(config_input)?;
        let secrets: SecretAppConfig = facet_styx::from_str(secrets_input)?;

        Ok(Self {
            control_plane: config.control_plane,
            subject: config.subject,
            relying: config.relying,
            bootstrap: BootstrapConfig {
                subject: config.bootstrap.subject,
                token: secrets.bootstrap.token,
                display_name: config.bootstrap.display_name,
            },
            jwt: JwtConfig {
                issuer: config.jwt.issuer,
                default_audience: config.jwt.default_audience,
                signing_private_key_file: config.jwt.signing_private_key_file,
                ttl_seconds: config.jwt.ttl_seconds,
            },
            feldera: FelderaConfig {
                enabled: config.feldera.enabled,
                base_url: config.feldera.base_url,
                pipeline_prefix: config.feldera.pipeline_prefix,
                readiness_probe: config.feldera.readiness_probe,
                api_key: secrets.feldera.and_then(|feldera| feldera.api_key),
                compile_profile: config.feldera.compile_profile,
                auto_start: config.feldera.auto_start,
                start_initial: config.feldera.start_initial,
            },
        })
    }

    pub fn schema() -> String {
        facet_styx::schema_from_type::<PublicAppConfig>()
    }

    pub fn secrets_schema() -> String {
        facet_styx::schema_from_type::<SecretAppConfig>()
    }
}

impl ListenerConfig {
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl JwtConfig {
    pub fn signing_private_key_path(&self, config_dir: &Path) -> PathBuf {
        if self.signing_private_key_file.is_absolute() {
            self.signing_private_key_file.clone()
        } else {
            config_dir.join(&self.signing_private_key_file)
        }
    }

    pub fn signing_private_key_bytes(&self, config_dir: &Path) -> Result<[u8; 32], DynError> {
        let path = self.signing_private_key_path(config_dir);
        let pem = read_required_file(&path, "jwt signing private key")?;
        decode_signing_private_key_pem(&pem, &path)
    }
}

impl LoadedConfig {
    pub fn signing_private_key_bytes(&self) -> Result<[u8; 32], DynError> {
        self.config.jwt.signing_private_key_bytes(&self.config_dir)
    }
}

#[derive(Debug, Parser)]
#[command(name = "conclave-server")]
struct StartupOverrides {
    #[arg(long, env = "CONCLAVE_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long, env = "CONCLAVE_SECRETS")]
    secrets: Option<PathBuf>,
    #[arg(long, env = "CONCLAVE_MANAGED_DIR")]
    managed_dir: Option<PathBuf>,
    #[arg(long, env = "CONCLAVE_CONTROL_PLANE_HOST")]
    control_plane_host: Option<String>,
    #[arg(long, env = "CONCLAVE_CONTROL_PLANE_PORT")]
    control_plane_port: Option<u16>,
    #[arg(long, env = "CONCLAVE_SUBJECT_HOST")]
    subject_host: Option<String>,
    #[arg(long, env = "CONCLAVE_SUBJECT_PORT")]
    subject_port: Option<u16>,
    #[arg(long, env = "CONCLAVE_RELYING_HOST")]
    relying_host: Option<String>,
    #[arg(long, env = "CONCLAVE_RELYING_PORT")]
    relying_port: Option<u16>,
    #[arg(long, env = "CONCLAVE_BOOTSTRAP_SUBJECT")]
    bootstrap_subject: Option<String>,
    #[arg(long, env = "CONCLAVE_BOOTSTRAP_DISPLAY_NAME")]
    bootstrap_display_name: Option<String>,
    #[arg(long, env = "CONCLAVE_JWT_ISSUER")]
    jwt_issuer: Option<String>,
    #[arg(long, env = "CONCLAVE_JWT_DEFAULT_AUDIENCE")]
    jwt_default_audience: Option<String>,
    #[arg(long, env = "CONCLAVE_JWT_SIGNING_PRIVATE_KEY_FILE")]
    jwt_signing_private_key_file: Option<PathBuf>,
    #[arg(long, env = "CONCLAVE_JWT_TTL_SECONDS")]
    jwt_ttl_seconds: Option<u64>,
    #[arg(long, env = "CONCLAVE_FELDERA_ENABLED")]
    feldera_enabled: Option<bool>,
    #[arg(long, env = "CONCLAVE_FELDERA_BASE_URL")]
    feldera_base_url: Option<String>,
    #[arg(long, env = "CONCLAVE_FELDERA_PIPELINE_PREFIX")]
    feldera_pipeline_prefix: Option<String>,
    #[arg(long, env = "CONCLAVE_FELDERA_READINESS_PROBE")]
    feldera_readiness_probe: Option<bool>,
    #[arg(long, env = "CONCLAVE_FELDERA_COMPILE_PROFILE")]
    feldera_compile_profile: Option<String>,
    #[arg(long, env = "CONCLAVE_FELDERA_AUTO_START")]
    feldera_auto_start: Option<bool>,
    #[arg(long, env = "CONCLAVE_FELDERA_START_INITIAL")]
    feldera_start_initial: Option<String>,
}

impl StartupOverrides {
    fn parse<I, T>(args: I) -> Result<(Self, OverrideSources), DynError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let mut command = Self::command();
        let matches = command.try_get_matches_from_mut(args)?;
        let overrides = Self::from_arg_matches(&matches)?;
        let sources = OverrideSources::from_matches(&matches);

        Ok((overrides, sources))
    }

    fn apply_to(self, config: &mut AppConfig, managed_dir: &mut PathBuf) {
        apply_override(&mut config.control_plane.host, self.control_plane_host);
        apply_override(&mut config.control_plane.port, self.control_plane_port);
        apply_override(&mut config.subject.host, self.subject_host);
        apply_override(&mut config.subject.port, self.subject_port);
        apply_override(&mut config.relying.host, self.relying_host);
        apply_override(&mut config.relying.port, self.relying_port);
        apply_override(&mut config.bootstrap.subject, self.bootstrap_subject);
        apply_optional_override(
            &mut config.bootstrap.display_name,
            self.bootstrap_display_name,
        );
        apply_override(&mut config.jwt.issuer, self.jwt_issuer);
        apply_override(&mut config.jwt.default_audience, self.jwt_default_audience);
        apply_override(
            &mut config.jwt.signing_private_key_file,
            self.jwt_signing_private_key_file,
        );
        apply_override(&mut config.jwt.ttl_seconds, self.jwt_ttl_seconds);
        apply_override(&mut config.feldera.enabled, self.feldera_enabled);
        apply_override(&mut config.feldera.base_url, self.feldera_base_url);
        apply_override(
            &mut config.feldera.pipeline_prefix,
            self.feldera_pipeline_prefix,
        );
        apply_override(
            &mut config.feldera.readiness_probe,
            self.feldera_readiness_probe,
        );
        apply_override(
            &mut config.feldera.compile_profile,
            self.feldera_compile_profile,
        );
        apply_override(&mut config.feldera.auto_start, self.feldera_auto_start);
        apply_override(
            &mut config.feldera.start_initial,
            self.feldera_start_initial,
        );
        apply_override(managed_dir, self.managed_dir);
    }
}

#[derive(Debug, Default)]
struct OverrideSources {
    flags: Vec<&'static str>,
    env: Vec<&'static str>,
}

impl OverrideSources {
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        let mut sources = Self::default();
        for (id, flag, env_name) in [
            ("config", "--config", "CONCLAVE_CONFIG"),
            ("secrets", "--secrets", "CONCLAVE_SECRETS"),
            ("managed_dir", "--managed-dir", "CONCLAVE_MANAGED_DIR"),
            (
                "control_plane_host",
                "--control-plane-host",
                "CONCLAVE_CONTROL_PLANE_HOST",
            ),
            (
                "control_plane_port",
                "--control-plane-port",
                "CONCLAVE_CONTROL_PLANE_PORT",
            ),
            ("subject_host", "--subject-host", "CONCLAVE_SUBJECT_HOST"),
            ("subject_port", "--subject-port", "CONCLAVE_SUBJECT_PORT"),
            ("relying_host", "--relying-host", "CONCLAVE_RELYING_HOST"),
            ("relying_port", "--relying-port", "CONCLAVE_RELYING_PORT"),
            (
                "bootstrap_subject",
                "--bootstrap-subject",
                "CONCLAVE_BOOTSTRAP_SUBJECT",
            ),
            (
                "bootstrap_display_name",
                "--bootstrap-display-name",
                "CONCLAVE_BOOTSTRAP_DISPLAY_NAME",
            ),
            ("jwt_issuer", "--jwt-issuer", "CONCLAVE_JWT_ISSUER"),
            (
                "jwt_default_audience",
                "--jwt-default-audience",
                "CONCLAVE_JWT_DEFAULT_AUDIENCE",
            ),
            (
                "jwt_signing_private_key_file",
                "--jwt-signing-private-key-file",
                "CONCLAVE_JWT_SIGNING_PRIVATE_KEY_FILE",
            ),
            (
                "jwt_ttl_seconds",
                "--jwt-ttl-seconds",
                "CONCLAVE_JWT_TTL_SECONDS",
            ),
            (
                "feldera_enabled",
                "--feldera-enabled",
                "CONCLAVE_FELDERA_ENABLED",
            ),
            (
                "feldera_base_url",
                "--feldera-base-url",
                "CONCLAVE_FELDERA_BASE_URL",
            ),
            (
                "feldera_pipeline_prefix",
                "--feldera-pipeline-prefix",
                "CONCLAVE_FELDERA_PIPELINE_PREFIX",
            ),
            (
                "feldera_readiness_probe",
                "--feldera-readiness-probe",
                "CONCLAVE_FELDERA_READINESS_PROBE",
            ),
            (
                "feldera_compile_profile",
                "--feldera-compile-profile",
                "CONCLAVE_FELDERA_COMPILE_PROFILE",
            ),
            (
                "feldera_auto_start",
                "--feldera-auto-start",
                "CONCLAVE_FELDERA_AUTO_START",
            ),
            (
                "feldera_start_initial",
                "--feldera-start-initial",
                "CONCLAVE_FELDERA_START_INITIAL",
            ),
        ] {
            match matches.value_source(id) {
                Some(ValueSource::CommandLine) => sources.flags.push(flag),
                Some(ValueSource::EnvVariable) => sources.env.push(env_name),
                _ => {}
            }
        }
        sources
    }
}

fn apply_override<T>(target: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *target = value;
    }
}

fn apply_optional_override<T>(target: &mut Option<T>, value: Option<T>) {
    if let Some(value) = value {
        *target = Some(value);
    }
}

fn managed_config_dir(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn read_required_file(path: &Path, label: &str) -> Result<String, DynError> {
    fs::read_to_string(path).map_err(|err| {
        Box::new(io::Error::new(
            err.kind(),
            format!("failed to read {label} file {}: {err}", path.display()),
        )) as DynError
    })
}

fn format_source(base: String, sources: &OverrideSources) -> String {
    let mut rendered = base;
    if !sources.env.is_empty() {
        rendered.push_str(" + env(");
        rendered.push_str(&sources.env.join(","));
        rendered.push(')');
    }
    if !sources.flags.is_empty() {
        rendered.push_str(" + flags(");
        rendered.push_str(&sources.flags.join(","));
        rendered.push(')');
    }
    rendered
}

fn reject_forbidden_entries(input: &str, label: &str, forbidden: &[&str]) -> Result<(), DynError> {
    for line in input.lines() {
        let trimmed = line.trim_start();
        for entry in forbidden {
            if let Some(rest) = trimmed.strip_prefix(entry) {
                let next = rest.chars().next();
                if matches!(next, Some(ch) if ch.is_whitespace() || ch == '{') {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{label} file must not define `{entry}`"),
                    )));
                }
            }
        }
    }

    Ok(())
}

fn decode_signing_private_key_pem(input: &str, path: &Path) -> Result<[u8; 32], DynError> {
    let trimmed = input.trim();
    let display = path.display();

    if trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "jwt signing private key file {display} must contain unencrypted PKCS#8 Ed25519 PEM, not OpenSSH private key data"
            ),
        )));
    }

    if trimmed.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "jwt signing private key file {display} must contain unencrypted PKCS#8 Ed25519 PEM"
            ),
        )));
    }

    if !trimmed.starts_with("-----BEGIN PRIVATE KEY-----") {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "jwt signing private key file {display} must contain unencrypted PKCS#8 Ed25519 PEM"
            ),
        )));
    }

    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(trimmed).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "jwt signing private key file {display} must contain a valid unencrypted PKCS#8 Ed25519 private key: {err}"
            ),
        )) as DynError
    })?;

    Ok(signing_key.to_bytes())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use pkcs8::LineEnding;

    use super::{AppConfig, LoadedConfig};

    fn public_config_styx() -> &'static str {
        r#"
control_plane {
    host "0.0.0.0"
    port 9090
}
subject {
    host "0.0.0.0"
    port 9091
}
relying {
    host "0.0.0.0"
    port 9092
}
bootstrap {
    subject "root-admin"
    display_name "Root Admin"
}
jwt {
    issuer "https://conclave.test"
    default_audience "clinic-api"
    signing_private_key_file "server.signing-private-key.pem"
    ttl_seconds 600
}
feldera {
    enabled true
    base_url "http://127.0.0.1:8088"
    pipeline_prefix "sandbox"
    readiness_probe false
    compile_profile "optimized"
    auto_start true
    start_initial "running"
}
"#
    }

    fn secrets_config_styx() -> &'static str {
        r#"
bootstrap {
    token "bootstrap-secret"
}
feldera {
    api_key "secret"
}
"#
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic enough for tests")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("conclave-server-config-{name}-{nonce}"));
        fs::create_dir_all(&dir).expect("temp test dir should be creatable");
        dir
    }

    fn write_file(path: &Path, contents: &str) {
        fs::write(path, contents).expect("test file should be writable");
    }

    fn signing_key_seed(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    fn signing_key_pem(seed: [u8; 32]) -> String {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("test signing key should encode to PKCS#8 PEM")
            .to_string()
    }

    fn write_signing_key_file(dir: &Path, seed: [u8; 32]) {
        write_file(
            &dir.join("server.signing-private-key.pem"),
            &signing_key_pem(seed),
        );
    }

    fn load_split_config_with_key(config_path: &Path, secrets_path: &Path) -> LoadedConfig {
        AppConfig::load_from([
            OsString::from("conclave-server"),
            OsString::from("--config"),
            config_path.as_os_str().to_os_string(),
            OsString::from("--secrets"),
            secrets_path.as_os_str().to_os_string(),
        ])
        .expect("config should load")
    }

    #[test]
    // r[verify platform.server.split-config-files]
    fn parses_split_styx_config() {
        let config = AppConfig::from_split_styx(public_config_styx(), secrets_config_styx())
            .expect("split styx config should parse");

        assert_eq!(config.control_plane.port, 9090);
        assert_eq!(config.subject.port, 9091);
        assert_eq!(config.relying.port, 9092);
        assert_eq!(config.bootstrap.subject, "root-admin");
        assert_eq!(config.bootstrap.token, "bootstrap-secret");
        assert_eq!(config.jwt.ttl_seconds, 600);
        assert_eq!(
            config.jwt.signing_private_key_file,
            PathBuf::from("server.signing-private-key.pem")
        );
        assert!(config.feldera.enabled);
        assert_eq!(config.feldera.api_key.as_deref(), Some("secret"));
    }

    #[test]
    fn emits_split_schemas() {
        let public_schema = AppConfig::schema();
        assert!(public_schema.contains("control_plane"));
        assert!(public_schema.contains("subject"));
        assert!(public_schema.contains("relying"));
        assert!(public_schema.contains("bootstrap"));
        assert!(public_schema.contains("ttl_seconds"));
        assert!(public_schema.contains("signing_private_key_file"));
        assert!(!public_schema.contains("signing_private_key "));
        assert!(!public_schema.contains("api_key"));

        let secrets_schema = AppConfig::secrets_schema();
        assert!(secrets_schema.contains("api_key"));
        assert!(secrets_schema.contains("token"));
        assert!(!secrets_schema.contains("control_plane"));
        assert!(!secrets_schema.contains("ttl_seconds"));
        assert!(!secrets_schema.contains("signing_private_key_file"));
    }

    #[test]
    // r[verify platform.server.explicit-secrets-path]
    fn applies_command_line_overrides() {
        let temp_dir = unique_temp_dir("flags");
        let config_path = temp_dir.join("custom-server.conf.styx");
        let secrets_path = temp_dir.join("custom-server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());
        write_signing_key_file(&temp_dir, signing_key_seed(0xAA));

        let loaded = AppConfig::load_from([
            OsString::from("conclave-server"),
            OsString::from("--config"),
            config_path.into_os_string(),
            OsString::from("--secrets"),
            secrets_path.into_os_string(),
            OsString::from("--control-plane-port"),
            OsString::from("9990"),
            OsString::from("--bootstrap-subject"),
            OsString::from("root-2"),
        ])
        .expect("config should load");

        assert_eq!(loaded.config.control_plane.port, 9990);
        assert_eq!(loaded.config.bootstrap.subject, "root-2");
        assert_eq!(
            loaded.config.jwt.signing_private_key_file,
            PathBuf::from("server.signing-private-key.pem")
        );
        assert!(loaded.source.contains("--secrets"));
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    // r[verify platform.server.explicit-secrets-path]
    fn applies_env_path_override_for_secrets_file() {
        let _guard = env_lock().lock().expect("env lock should be acquirable");
        let temp_dir = unique_temp_dir("env");
        let config_path = temp_dir.join("env-server.conf.styx");
        let secrets_path = temp_dir.join("env-server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());
        write_signing_key_file(&temp_dir, signing_key_seed(0xAB));

        std::env::set_var("CONCLAVE_CONFIG", &config_path);
        std::env::set_var("CONCLAVE_SECRETS", &secrets_path);
        std::env::set_var("CONCLAVE_CONTROL_PLANE_PORT", "9991");
        let loaded = AppConfig::load_from([OsString::from("conclave-server")])
            .expect("config should load from env-selected paths");

        assert_eq!(loaded.config.control_plane.port, 9991);
        assert_eq!(
            loaded.config.jwt.signing_private_key_file,
            PathBuf::from("server.signing-private-key.pem")
        );
        assert!(loaded.source.contains("CONCLAVE_SECRETS"));

        std::env::remove_var("CONCLAVE_CONFIG");
        std::env::remove_var("CONCLAVE_SECRETS");
        std::env::remove_var("CONCLAVE_CONTROL_PLANE_PORT");
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    // r[verify platform.server.split-config-files]
    // r[verify platform.server.strict-config-secrets-boundary]
    // r[verify platform.server.secret-file-only-values]
    fn rejects_secret_fields_in_public_config() {
        let err = AppConfig::from_split_styx(
            r#"
control_plane {
    host "0.0.0.0"
    port 9090
}
subject {
    host "0.0.0.0"
    port 9091
}
relying {
    host "0.0.0.0"
    port 9092
}
bootstrap {
    subject "root-admin"
    token "should-not-be-here"
}
jwt {
    issuer "https://conclave.test"
    default_audience "clinic-api"
    signing_private_key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    signing_private_key_file "server.signing-private-key.pem"
    ttl_seconds 600
}
feldera {
    enabled true
    base_url "http://127.0.0.1:8088"
    pipeline_prefix "sandbox"
    readiness_probe false
    compile_profile "optimized"
    auto_start true
    start_initial "running"
}
"#,
            secrets_config_styx(),
        )
        .expect_err("public config should reject secret fields");

        assert!(
            err.to_string().contains("token") || err.to_string().contains("signing_private_key")
        );
    }

    #[test]
    // r[verify platform.server.split-config-files]
    // r[verify platform.server.strict-config-secrets-boundary]
    // r[verify platform.server.secret-file-only-values]
    fn rejects_non_secret_fields_in_secrets_config() {
        let err = AppConfig::from_split_styx(
            public_config_styx(),
            r#"
bootstrap {
    token "bootstrap-secret"
    subject "should-not-be-here"
}
jwt {
    signing_private_key_file "server.signing-private-key.pem"
    ttl_seconds 600
}
"#,
        )
        .expect_err("secrets config should reject non-secret fields");

        assert!(err.to_string().contains("subject") || err.to_string().contains("ttl_seconds"));
    }

    #[test]
    // r[verify platform.server.split-config-files]
    fn missing_secrets_file_fails_clearly() {
        let temp_dir = unique_temp_dir("missing-secrets");
        let config_path = temp_dir.join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_signing_key_file(&temp_dir, signing_key_seed(0xAC));

        let err = AppConfig::load_from([
            OsString::from("conclave-server"),
            OsString::from("--config"),
            config_path.into_os_string(),
            OsString::from("--secrets"),
            secrets_path.into_os_string(),
        ])
        .expect_err("missing secrets file should fail");

        assert!(err.to_string().contains("failed to read secrets file"));
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    // r[verify platform.server.secret-file-only-values]
    fn rejects_removed_secret_flags() {
        for flag in ["--bootstrap-token", "--feldera-api-key"] {
            let err = AppConfig::load_from([
                OsString::from("conclave-server"),
                OsString::from(flag),
                OsString::from("secret"),
            ])
            .expect_err("removed secret flags should be rejected");

            assert!(err.to_string().contains(flag));
        }
    }

    #[test]
    // r[verify platform.server.secret-file-only-values]
    fn applies_signing_key_file_flag_override() {
        let temp_dir = unique_temp_dir("signing-key-flag");
        let config_path = temp_dir.join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        let override_key_path = temp_dir.join("override-signing-key.pem");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());
        write_signing_key_file(&temp_dir, signing_key_seed(0xAD));
        write_file(&override_key_path, &signing_key_pem(signing_key_seed(0xBC)));

        let loaded = AppConfig::load_from([
            OsString::from("conclave-server"),
            OsString::from("--config"),
            config_path.into_os_string(),
            OsString::from("--secrets"),
            secrets_path.into_os_string(),
            OsString::from("--jwt-signing-private-key-file"),
            override_key_path.into_os_string(),
        ])
        .expect("config should load");

        let bytes = loaded
            .signing_private_key_bytes()
            .expect("overridden signing key should parse");
        assert_eq!(bytes, signing_key_seed(0xBC));
        assert!(loaded.source.contains("--jwt-signing-private-key-file"));
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    // r[verify platform.server.secret-file-only-values]
    fn applies_signing_key_file_env_override() {
        let _guard = env_lock().lock().expect("env lock should be acquirable");
        let temp_dir = unique_temp_dir("signing-key-env");
        let config_path = temp_dir.join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        let override_key_path = temp_dir.join("env-signing-key.pem");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());
        write_signing_key_file(&temp_dir, signing_key_seed(0xAE));
        write_file(&override_key_path, &signing_key_pem(signing_key_seed(0xBD)));

        std::env::set_var("CONCLAVE_CONFIG", &config_path);
        std::env::set_var("CONCLAVE_SECRETS", &secrets_path);
        std::env::set_var("CONCLAVE_JWT_SIGNING_PRIVATE_KEY_FILE", &override_key_path);

        let loaded =
            AppConfig::load_from([OsString::from("conclave-server")]).expect("config should load");

        let bytes = loaded
            .signing_private_key_bytes()
            .expect("overridden signing key should parse");
        assert_eq!(bytes, signing_key_seed(0xBD));
        assert!(loaded
            .source
            .contains("CONCLAVE_JWT_SIGNING_PRIVATE_KEY_FILE"));

        std::env::remove_var("CONCLAVE_CONFIG");
        std::env::remove_var("CONCLAVE_SECRETS");
        std::env::remove_var("CONCLAVE_JWT_SIGNING_PRIVATE_KEY_FILE");
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    // r[verify platform.server.secret-file-only-values]
    fn ignores_removed_secret_env_overrides() {
        let _guard = env_lock().lock().expect("env lock should be acquirable");
        let temp_dir = unique_temp_dir("secret-env");
        let config_path = temp_dir.join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());
        write_signing_key_file(&temp_dir, signing_key_seed(0xAF));

        std::env::set_var("CONCLAVE_CONFIG", &config_path);
        std::env::set_var("CONCLAVE_SECRETS", &secrets_path);
        std::env::set_var("CONCLAVE_BOOTSTRAP_TOKEN", "ignored-bootstrap");
        std::env::set_var("CONCLAVE_FELDERA_API_KEY", "ignored-api-key");
        let loaded = AppConfig::load_from([OsString::from("conclave-server")])
            .expect("config should ignore removed secret env overrides");

        assert_eq!(loaded.config.bootstrap.token, "bootstrap-secret");
        assert_eq!(
            loaded.config.jwt.signing_private_key_file,
            PathBuf::from("server.signing-private-key.pem")
        );
        assert_eq!(loaded.config.feldera.api_key.as_deref(), Some("secret"));

        std::env::remove_var("CONCLAVE_CONFIG");
        std::env::remove_var("CONCLAVE_SECRETS");
        std::env::remove_var("CONCLAVE_BOOTSTRAP_TOKEN");
        std::env::remove_var("CONCLAVE_FELDERA_API_KEY");
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    fn loaded_split_config_still_builds_signer_inputs() {
        let temp_dir = unique_temp_dir("signing-key-load");
        let config_path = temp_dir.join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());
        write_signing_key_file(&temp_dir, signing_key_seed(0xBE));

        let loaded = load_split_config_with_key(&config_path, &secrets_path);
        let bytes = loaded
            .signing_private_key_bytes()
            .expect("signing key should decode");

        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, signing_key_seed(0xBE));
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    fn signing_key_path_is_resolved_relative_to_public_config() {
        let temp_dir = unique_temp_dir("relative-signing-key");
        let config_path = temp_dir.join("nested").join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        fs::create_dir_all(
            config_path
                .parent()
                .expect("nested config dir should exist"),
        )
        .expect("nested config dir should be creatable");
        write_file(
            &config_path,
            &public_config_styx().replace(
                "server.signing-private-key.pem",
                "keys/relative-signing-key.pem",
            ),
        );
        write_file(&secrets_path, secrets_config_styx());
        let key_dir = config_path
            .parent()
            .expect("config path should have parent")
            .join("keys");
        fs::create_dir_all(&key_dir).expect("key dir should be creatable");
        write_file(
            &key_dir.join("relative-signing-key.pem"),
            &signing_key_pem(signing_key_seed(0xBF)),
        );

        let loaded = load_split_config_with_key(&config_path, &secrets_path);
        let bytes = loaded
            .signing_private_key_bytes()
            .expect("relative signing key should parse");

        assert_eq!(bytes, signing_key_seed(0xBF));
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    fn missing_signing_key_file_fails_clearly() {
        let temp_dir = unique_temp_dir("missing-signing-key");
        let config_path = temp_dir.join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());

        let loaded = load_split_config_with_key(&config_path, &secrets_path);
        let err = loaded
            .signing_private_key_bytes()
            .expect_err("missing signing key file should fail");

        assert!(err
            .to_string()
            .contains("failed to read jwt signing private key file"));
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    fn rejects_invalid_signing_key_formats() {
        let temp_dir = unique_temp_dir("invalid-signing-key");
        let config_path = temp_dir.join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());

        for (name, contents, expected) in [
            ("raw-hex.pem", "01020304", "PKCS#8 Ed25519 PEM"),
            (
                "openssh.pem",
                "-----BEGIN OPENSSH PRIVATE KEY-----\nZm9v\n-----END OPENSSH PRIVATE KEY-----\n",
                "OpenSSH private key data",
            ),
            (
                "encrypted.pem",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZm9v\n-----END ENCRYPTED PRIVATE KEY-----\n",
                "unencrypted PKCS#8 Ed25519 PEM",
            ),
            (
                "rsa.pem",
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD4+F58N7p6RJJi\nmVg86aLRTF44S36Jv6fdxM7qQaP7Mu7apORdzdrIW6DCeU44yWiNysGEKMluSleq\n9jwELyhl725LLJoPLD114F8CbnMD4HzyBbs6k8ZZrVSu2Ce279b9Ec/WWEDuJeay\nZT6X0hgqP/d9vywgq6Z9erjRzCQXDpUe1koXSPo6e7iLF730cdpShUMHbOWcZH/5\nnYI8aAizI0s5momkMumZ5qX6Ch12yvDqOiiMHDL/95B2S/bRMyCV2wAPOQgpdnXl\n16rYPD+s/COM24kTx5cDIeEJD7BqXc9E+u6KDAdAm8YGtS+wGGyRyvE4s46HoPaz\n/gkGEXLFAgMBAAECggEABToYtL6vhfVqlhK/SXxPxq8np5xpoE2mR7BfrpsbR9f7\nDmqDveoxu48UUfZo0Sy0RKZ77N8BINU3CFAaj6MqFmoVoeAQMtk0iA0WIMRqjYOE\nTP0TO+GfY+3CX6XcncxZV8oPZxC25fRT5tne342XQIjd/OQvPsvBLnBxGZ+rsoAh\nm6q+UpBAkLTlaX2UjsFvdcGaVbL50DJBSSTXobHxPPH/FkOFjvFsRQAt2bQVWwtD\nY9ycYzaO+VxDRKCVh0b07XHtcwPa5RW2XnwI75E+BGzb62LF8A3+yQUwSWOSJyjt\ncmBHQYaWV7k/akdUSHh3D1ynjUTduVdJN9WewtG/XQKBgQD+R5c+3F4iAfDdc0AG\n/7uWGINuD/7++UZ5EONosFVJeFt3PcTJS3BM4tiTqcKoy0eZZ+j9RnBbTK1ZBOqV\nakiobP6KyHR+Y6SY+4PSJVpaz6RtWLpmjHtkobaN6D+PfYZ7R6pujISiFDUFxIr2\nle3NbS1Ry6j8TDIrS9KuX3sI5QKBgQD5cjox96D65gis6pZeRAEIJ5zsxFrqOeEf\nzY4xXHzkwmo7aX6ixkmKuuNHYsYvwP82LPgAvFp8ZUBKbjsgg7sWXBJgp7wa9u0J\npKnz03Wx/89ZbduCMsZ/HXXIQK5vCk1vZEBtcHTTX3e8DqRLVQjaxAg/P6MqxsVX\npYWh05rq6wKBgQDXxpv8uKXuX4nHCqB6f+GO6zkRgZNpmjQe7YQDdyCjTiMQuuLH\nfoalGexiLRNvKcJsteVEh9UpAJZciV06P88eaJEqn3Ejj6inUeJ8V+RaHcRUW2KI\nMzFxLpy0X58F3RrgPf63eNbUsVTNff7kwh28ykVfoCkb0z7LxyzKDn5X7QKBgDya\nL7sRKqzZo4PMBVXgS5aXoaZySUdkGFUTkOcJCIZy9FHn5Vf3L7hIwrKyYVJZZzK9\nedvurIWBLL8GMDIS9ZhDJW60Agw7P3cu6UytzszbmWzxubUoil58x2oyS9MhUlCT\nVkOITkkpFmS6r30YIOCQM7DDDeWGPAHDLcGRIDcRAoGAfNruM3aMcMBXNIN1qNbf\nWf9eKJeNEqXWiwxupCSvJzpuG1HsRvN7kYM/qfNwCuWHa3gwxM/H2ymlk/wEYBLET\nFcpnSUsctNk6heAQ7EzxKJ0C5EvhczHxVn9Yx8RJWb1x1o1t4bm/FvGV8eK3opgDd\nYqKqRR3YKHyCuXapnwXCfJ0=\n-----END PRIVATE KEY-----\n",
                "Ed25519 private key",
            ),
        ] {
            write_file(&temp_dir.join(name), contents);
            let loaded = AppConfig::load_from([
                OsString::from("conclave-server"),
                OsString::from("--config"),
                config_path.as_os_str().to_os_string(),
                OsString::from("--secrets"),
                secrets_path.as_os_str().to_os_string(),
                OsString::from("--jwt-signing-private-key-file"),
                temp_dir.join(name).into_os_string(),
            ])
            .expect("config should load");

            let err = loaded
                .signing_private_key_bytes()
                .expect_err("invalid signing key format should fail");
            assert!(err.to_string().contains(expected), "{name}: {err}");
        }

        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }
}
