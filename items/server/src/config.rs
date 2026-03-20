use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser};
use facet::Facet;
use serde::Deserialize;

type DynError = Box<dyn std::error::Error + Send + Sync>;

const DEFAULT_CONFIG_PATH: &str = "config/server.conf.styx";
const DEFAULT_SECRETS_PATH: &str = "config/server.secrets.styx";

#[derive(Clone, Debug)]
pub struct LoadedConfig {
    pub config: AppConfig,
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
    pub signing_private_key: String,
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
    jwt: SecretJwtConfig,
    feldera: Option<SecretFelderaConfig>,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct SecretBootstrapConfig {
    token: String,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
#[serde(deny_unknown_fields)]
struct SecretJwtConfig {
    signing_private_key: String,
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
                signing_private_key:
                    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_owned(),
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
        let config_contents = read_required_file(&config_path, "config")?;
        let secrets_contents = read_required_file(&secrets_path, "secrets")?;
        let mut config = Self::from_split_styx(&config_contents, &secrets_contents)?;

        overrides.apply_to(&mut config, &mut managed_dir);

        Ok(LoadedConfig {
            config,
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
                signing_private_key: secrets.jwt.signing_private_key,
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
    pub fn signing_private_key_bytes(&self) -> Result<[u8; 32], DynError> {
        let bytes = decode_hex(&self.signing_private_key)?;
        bytes.try_into().map_err(|_| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "jwt signing private key must decode to 32 bytes",
            )) as DynError
        })
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

fn decode_hex(input: &str) -> Result<Vec<u8>, DynError> {
    if input.len() % 2 != 0 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hex input must have even length",
        )));
    }

    let mut bytes = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk)?;
        bytes.push(u8::from_str_radix(pair, 16)?);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::AppConfig;

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
jwt {
    signing_private_key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
            config.jwt.signing_private_key,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
        assert!(!public_schema.contains("signing_private_key"));
        assert!(!public_schema.contains("api_key"));

        let secrets_schema = AppConfig::secrets_schema();
        assert!(secrets_schema.contains("signing_private_key"));
        assert!(secrets_schema.contains("api_key"));
        assert!(secrets_schema.contains("token"));
        assert!(!secrets_schema.contains("control_plane"));
        assert!(!secrets_schema.contains("ttl_seconds"));
    }

    #[test]
    // r[verify platform.server.explicit-secrets-path]
    fn applies_command_line_overrides() {
        let temp_dir = unique_temp_dir("flags");
        let config_path = temp_dir.join("custom-server.conf.styx");
        let secrets_path = temp_dir.join("custom-server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());

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
            loaded.config.jwt.signing_private_key,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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

        std::env::set_var("CONCLAVE_CONFIG", &config_path);
        std::env::set_var("CONCLAVE_SECRETS", &secrets_path);
        std::env::set_var("CONCLAVE_CONTROL_PLANE_PORT", "9991");
        let loaded = AppConfig::load_from([OsString::from("conclave-server")])
            .expect("config should load from env-selected paths");

        assert_eq!(loaded.config.control_plane.port, 9991);
        assert_eq!(
            loaded.config.jwt.signing_private_key,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
    signing_private_key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
        for flag in [
            "--bootstrap-token",
            "--jwt-signing-private-key",
            "--feldera-api-key",
        ] {
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
    fn ignores_removed_secret_env_overrides() {
        let _guard = env_lock().lock().expect("env lock should be acquirable");
        let temp_dir = unique_temp_dir("secret-env");
        let config_path = temp_dir.join("server.conf.styx");
        let secrets_path = temp_dir.join("server.secrets.styx");
        write_file(&config_path, public_config_styx());
        write_file(&secrets_path, secrets_config_styx());

        std::env::set_var("CONCLAVE_CONFIG", &config_path);
        std::env::set_var("CONCLAVE_SECRETS", &secrets_path);
        std::env::set_var("CONCLAVE_BOOTSTRAP_TOKEN", "ignored-bootstrap");
        std::env::set_var(
            "CONCLAVE_JWT_SIGNING_PRIVATE_KEY",
            "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
        );
        std::env::set_var("CONCLAVE_FELDERA_API_KEY", "ignored-api-key");
        let loaded = AppConfig::load_from([OsString::from("conclave-server")])
            .expect("config should ignore removed secret env overrides");

        assert_eq!(loaded.config.bootstrap.token, "bootstrap-secret");
        assert_eq!(
            loaded.config.jwt.signing_private_key,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(loaded.config.feldera.api_key.as_deref(), Some("secret"));

        std::env::remove_var("CONCLAVE_CONFIG");
        std::env::remove_var("CONCLAVE_SECRETS");
        std::env::remove_var("CONCLAVE_BOOTSTRAP_TOKEN");
        std::env::remove_var("CONCLAVE_JWT_SIGNING_PRIVATE_KEY");
        std::env::remove_var("CONCLAVE_FELDERA_API_KEY");
        fs::remove_dir_all(&temp_dir).expect("temp test dir should be removable");
    }

    #[test]
    fn loaded_split_config_still_builds_signer_inputs() {
        let config = AppConfig::from_split_styx(public_config_styx(), secrets_config_styx())
            .expect("split styx config should parse");

        let bytes = config
            .jwt
            .signing_private_key_bytes()
            .expect("signing key should decode");

        assert_eq!(bytes.len(), 32);
    }
}
