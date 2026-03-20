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

const DEFAULT_CONFIG_PATH: &str = "config/server.styx";

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
    pub fn load() -> Result<LoadedConfig, DynError> {
        Self::load_from(env::args_os())
    }

    fn load_from<I, T>(args: I) -> Result<LoadedConfig, DynError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let (overrides, override_sources) = StartupOverrides::parse(args)?;
        let path = overrides
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        let mut managed_dir = managed_config_dir(&path);

        let (mut config, source) = match fs::read_to_string(&path) {
            Ok(contents) => (
                Self::from_styx(&contents)?,
                format!("file:{}", path.display()),
            ),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                (Self::default(), "built-in defaults".to_owned())
            }
            Err(err) => return Err(Box::new(err)),
        };

        overrides.apply_to(&mut config, &mut managed_dir);

        Ok(LoadedConfig {
            config,
            managed_dir,
            source: format_source(source, &override_sources),
        })
    }

    pub fn from_styx(input: &str) -> Result<Self, DynError> {
        Ok(facet_styx::from_str(input)?)
    }

    pub fn schema() -> String {
        facet_styx::schema_from_type::<Self>()
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
    #[arg(long, env = "CONCLAVE_BOOTSTRAP_TOKEN")]
    bootstrap_token: Option<String>,
    #[arg(long, env = "CONCLAVE_BOOTSTRAP_DISPLAY_NAME")]
    bootstrap_display_name: Option<String>,
    #[arg(long, env = "CONCLAVE_JWT_ISSUER")]
    jwt_issuer: Option<String>,
    #[arg(long, env = "CONCLAVE_JWT_DEFAULT_AUDIENCE")]
    jwt_default_audience: Option<String>,
    #[arg(long, env = "CONCLAVE_JWT_SIGNING_PRIVATE_KEY")]
    jwt_signing_private_key: Option<String>,
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
    #[arg(long, env = "CONCLAVE_FELDERA_API_KEY")]
    feldera_api_key: Option<String>,
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
        apply_override(&mut config.bootstrap.token, self.bootstrap_token);
        apply_optional_override(
            &mut config.bootstrap.display_name,
            self.bootstrap_display_name,
        );
        apply_override(&mut config.jwt.issuer, self.jwt_issuer);
        apply_override(&mut config.jwt.default_audience, self.jwt_default_audience);
        apply_override(
            &mut config.jwt.signing_private_key,
            self.jwt_signing_private_key,
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
        apply_optional_override(&mut config.feldera.api_key, self.feldera_api_key);
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
                "bootstrap_token",
                "--bootstrap-token",
                "CONCLAVE_BOOTSTRAP_TOKEN",
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
                "jwt_signing_private_key",
                "--jwt-signing-private-key",
                "CONCLAVE_JWT_SIGNING_PRIVATE_KEY",
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
                "feldera_api_key",
                "--feldera-api-key",
                "CONCLAVE_FELDERA_API_KEY",
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

    use super::AppConfig;

    #[test]
    fn parses_styx_config() {
        let config = AppConfig::from_styx(
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
    token "bootstrap-secret"
    display_name "Root Admin"
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
    api_key "secret"
    compile_profile "optimized"
    auto_start true
    start_initial "running"
}
"#,
        )
        .expect("styx config should parse");

        assert_eq!(config.control_plane.port, 9090);
        assert_eq!(config.subject.port, 9091);
        assert_eq!(config.relying.port, 9092);
        assert_eq!(config.bootstrap.subject, "root-admin");
        assert_eq!(config.jwt.ttl_seconds, 600);
        assert!(config.feldera.enabled);
    }

    #[test]
    fn emits_schema() {
        let schema = AppConfig::schema();
        assert!(schema.contains("control_plane"));
        assert!(schema.contains("subject"));
        assert!(schema.contains("relying"));
        assert!(schema.contains("bootstrap"));
        assert!(schema.contains("signing_private_key"));
    }

    #[test]
    fn applies_command_line_overrides() {
        let loaded = AppConfig::load_from([
            OsString::from("conclave-server"),
            OsString::from("--control-plane-port"),
            OsString::from("9990"),
            OsString::from("--bootstrap-subject"),
            OsString::from("root-2"),
            OsString::from("--jwt-signing-private-key"),
            OsString::from("02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"),
        ])
        .expect("config should load");

        assert_eq!(loaded.config.control_plane.port, 9990);
        assert_eq!(loaded.config.bootstrap.subject, "root-2");
        assert_eq!(
            loaded.config.jwt.signing_private_key,
            "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"
        );
    }
}
