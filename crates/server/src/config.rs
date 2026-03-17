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
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub feldera: FelderaConfig,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Facet, PartialEq)]
pub struct JwtConfig {
    pub issuer: String,
    pub default_audience: String,
    pub signing_secret: String,
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
            server: ServerConfig {
                host: "127.0.0.1".to_owned(),
                port: 8080,
            },
            jwt: JwtConfig {
                issuer: "http://127.0.0.1:8080".to_owned(),
                default_audience: "conclave-dev".to_owned(),
                signing_secret: "conclave-dev-secret".to_owned(),
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
    pub fn load() -> Result<LoadedConfig, DynError> {
        Self::load_from(env::args_os())
    }

    fn load_from<I, T>(args: I) -> Result<LoadedConfig, DynError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let (overrides, override_sources) = StartupOverrides::parse(args)?;
        let configured_path = overrides
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        let path = configured_path;
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

        let source = format_source(source, &override_sources);

        Ok(LoadedConfig {
            config,
            managed_dir,
            source,
        })
    }

    pub fn from_styx(input: &str) -> Result<Self, DynError> {
        Ok(facet_styx::from_str(input)?)
    }

    pub fn schema() -> String {
        facet_styx::schema_from_type::<Self>()
    }
}

#[derive(Debug, Parser)]
#[command(name = "conclave-server")]
struct StartupOverrides {
    #[arg(long, env = "CONCLAVE_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long, env = "CONCLAVE_MANAGED_DIR")]
    managed_dir: Option<PathBuf>,
    #[arg(long, env = "CONCLAVE_SERVER_HOST")]
    server_host: Option<String>,
    #[arg(long, env = "CONCLAVE_SERVER_PORT")]
    server_port: Option<u16>,
    #[arg(long, env = "CONCLAVE_JWT_ISSUER")]
    jwt_issuer: Option<String>,
    #[arg(long, env = "CONCLAVE_JWT_DEFAULT_AUDIENCE")]
    jwt_default_audience: Option<String>,
    #[arg(long, env = "CONCLAVE_JWT_SIGNING_SECRET")]
    jwt_signing_secret: Option<String>,
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
        apply_override(&mut config.server.host, self.server_host);
        apply_override(&mut config.server.port, self.server_port);
        apply_override(&mut config.jwt.issuer, self.jwt_issuer);
        apply_override(&mut config.jwt.default_audience, self.jwt_default_audience);
        apply_override(&mut config.jwt.signing_secret, self.jwt_signing_secret);
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

impl ServerConfig {
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn managed_config_dir(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
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

impl OverrideSources {
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        let mut sources = Self::default();

        record_override_source(
            matches,
            "config",
            "--config",
            "CONCLAVE_CONFIG",
            &mut sources,
        );
        record_override_source(
            matches,
            "managed_dir",
            "--managed-dir",
            "CONCLAVE_MANAGED_DIR",
            &mut sources,
        );
        record_override_source(
            matches,
            "server_host",
            "--server-host",
            "CONCLAVE_SERVER_HOST",
            &mut sources,
        );
        record_override_source(
            matches,
            "server_port",
            "--server-port",
            "CONCLAVE_SERVER_PORT",
            &mut sources,
        );
        record_override_source(
            matches,
            "jwt_issuer",
            "--jwt-issuer",
            "CONCLAVE_JWT_ISSUER",
            &mut sources,
        );
        record_override_source(
            matches,
            "jwt_default_audience",
            "--jwt-default-audience",
            "CONCLAVE_JWT_DEFAULT_AUDIENCE",
            &mut sources,
        );
        record_override_source(
            matches,
            "jwt_signing_secret",
            "--jwt-signing-secret",
            "CONCLAVE_JWT_SIGNING_SECRET",
            &mut sources,
        );
        record_override_source(
            matches,
            "jwt_ttl_seconds",
            "--jwt-ttl-seconds",
            "CONCLAVE_JWT_TTL_SECONDS",
            &mut sources,
        );
        record_override_source(
            matches,
            "feldera_enabled",
            "--feldera-enabled",
            "CONCLAVE_FELDERA_ENABLED",
            &mut sources,
        );
        record_override_source(
            matches,
            "feldera_base_url",
            "--feldera-base-url",
            "CONCLAVE_FELDERA_BASE_URL",
            &mut sources,
        );
        record_override_source(
            matches,
            "feldera_pipeline_prefix",
            "--feldera-pipeline-prefix",
            "CONCLAVE_FELDERA_PIPELINE_PREFIX",
            &mut sources,
        );
        record_override_source(
            matches,
            "feldera_readiness_probe",
            "--feldera-readiness-probe",
            "CONCLAVE_FELDERA_READINESS_PROBE",
            &mut sources,
        );
        record_override_source(
            matches,
            "feldera_api_key",
            "--feldera-api-key",
            "CONCLAVE_FELDERA_API_KEY",
            &mut sources,
        );
        record_override_source(
            matches,
            "feldera_compile_profile",
            "--feldera-compile-profile",
            "CONCLAVE_FELDERA_COMPILE_PROFILE",
            &mut sources,
        );
        record_override_source(
            matches,
            "feldera_auto_start",
            "--feldera-auto-start",
            "CONCLAVE_FELDERA_AUTO_START",
            &mut sources,
        );
        record_override_source(
            matches,
            "feldera_start_initial",
            "--feldera-start-initial",
            "CONCLAVE_FELDERA_START_INITIAL",
            &mut sources,
        );

        sources
    }
}

fn record_override_source(
    matches: &clap::ArgMatches,
    id: &str,
    flag_label: &'static str,
    env_label: &'static str,
    sources: &mut OverrideSources,
) {
    match matches.value_source(id) {
        Some(ValueSource::CommandLine) => sources.flags.push(flag_label),
        Some(ValueSource::EnvVariable) => sources.env.push(env_label),
        _ => {}
    }
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

#[cfg(test)]
mod tests {
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::AppConfig;

    // r[verify platform.server.bootstrap]
    #[test]
    fn parses_styx_config() {
        let config = AppConfig::from_styx(
            r#"
server {
    host "0.0.0.0"
    port 9090
}
jwt {
    issuer "https://conclave.test"
    default_audience "clinic-api"
    signing_secret "secret-key"
    ttl_seconds 600
}
feldera {
    enabled true
    base_url "http://127.0.0.1:8081"
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

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 9090);
        assert_eq!(config.jwt.issuer, "https://conclave.test");
        assert_eq!(config.jwt.default_audience, "clinic-api");
        assert_eq!(config.jwt.signing_secret, "secret-key");
        assert_eq!(config.jwt.ttl_seconds, 600);
        assert!(config.feldera.enabled);
        assert_eq!(config.feldera.pipeline_prefix, "sandbox");
        assert!(!config.feldera.readiness_probe);
        assert_eq!(config.feldera.api_key.as_deref(), Some("secret"));
        assert_eq!(config.feldera.compile_profile, "optimized");
        assert!(config.feldera.auto_start);
        assert_eq!(config.feldera.start_initial, "running");
    }

    #[test]
    fn emits_schema() {
        let schema = AppConfig::schema();

        assert!(schema.contains("server"));
        assert!(schema.contains("jwt"));
        assert!(schema.contains("feldera"));
        assert!(schema.contains("pipeline_prefix"));
    }

    #[test]
    fn applies_command_line_overrides() {
        let _guard = env_lock().lock().expect("env mutex should lock");
        let env_guard = ScopedEnv::clear_all();
        let config_path = write_config(
            "server-cli",
            r#"
server {
    host "127.0.0.1"
    port 8080
}
jwt {
    issuer "http://127.0.0.1:8080"
    default_audience "conclave-dev"
    signing_secret "secret"
    ttl_seconds 900
}
feldera {
    enabled false
    base_url "http://127.0.0.1:8080"
    pipeline_prefix "conclave"
    readiness_probe true
    compile_profile "dev"
    auto_start false
    start_initial "paused"
}
"#,
        );

        let loaded = AppConfig::load_from([
            OsString::from("conclave-server"),
            OsString::from("--config"),
            config_path.as_os_str().to_owned(),
            OsString::from("--server-host"),
            OsString::from("0.0.0.0"),
            OsString::from("--server-port"),
            OsString::from("9090"),
            OsString::from("--feldera-enabled"),
            OsString::from("true"),
        ])
        .expect("config should load with command line overrides");

        assert_eq!(loaded.config.server.host, "0.0.0.0");
        assert_eq!(loaded.config.server.port, 9090);
        assert!(loaded.config.feldera.enabled);
        assert!(loaded
            .source
            .contains("flags(--config,--server-host,--server-port,--feldera-enabled)"));
        drop(env_guard);
    }

    #[test]
    fn command_line_overrides_take_precedence_over_env() {
        let _guard = env_lock().lock().expect("env mutex should lock");
        let mut env_guard = ScopedEnv::clear_all();
        let config_path = write_config(
            "server-env-precedence",
            r#"
server {
    host "127.0.0.1"
    port 8080
}
jwt {
    issuer "http://127.0.0.1:8080"
    default_audience "conclave-dev"
    signing_secret "secret"
    ttl_seconds 900
}
feldera {
    enabled false
    base_url "http://127.0.0.1:8080"
    pipeline_prefix "conclave"
    readiness_probe true
    compile_profile "dev"
    auto_start false
    start_initial "paused"
}
"#,
        );

        env_guard.set("CONCLAVE_SERVER_HOST", "env-host");
        env_guard.set("CONCLAVE_FELDERA_ENABLED", "false");

        let loaded = AppConfig::load_from([
            OsString::from("conclave-server"),
            OsString::from("--config"),
            config_path.as_os_str().to_owned(),
            OsString::from("--server-host"),
            OsString::from("flag-host"),
            OsString::from("--feldera-enabled"),
            OsString::from("true"),
        ])
        .expect("config should load with mixed overrides");

        assert_eq!(loaded.config.server.host, "flag-host");
        assert!(loaded.config.feldera.enabled);
        assert!(!loaded.source.contains("CONCLAVE_SERVER_HOST"));
        assert!(loaded
            .source
            .contains("flags(--config,--server-host,--feldera-enabled)"));
    }

    fn write_config(prefix: &str, contents: &str) -> PathBuf {
        let path = temp_dir(prefix).join("server.styx");
        fs::write(&path, contents).expect("config file should write");
        path
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{nanos}"));
        fs::create_dir_all(&dir).expect("temp dir should create");
        dir
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct ScopedEnv {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl ScopedEnv {
        fn clear_all() -> Self {
            let mut saved = Vec::with_capacity(CONCLAVE_ENV_VARS.len());

            for name in CONCLAVE_ENV_VARS {
                saved.push((*name, env::var_os(name)));
                env::remove_var(name);
            }

            Self { saved }
        }

        fn set(&mut self, name: &'static str, value: &str) {
            if !self.saved.iter().any(|(saved_name, _)| *saved_name == name) {
                self.saved.push((name, env::var_os(name)));
            }

            env::set_var(name, value);
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            for (name, value) in self.saved.drain(..).rev() {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }
    }

    const CONCLAVE_ENV_VARS: &[&str] = &[
        "CONCLAVE_CONFIG",
        "CONCLAVE_MANAGED_DIR",
        "CONCLAVE_SERVER_HOST",
        "CONCLAVE_SERVER_PORT",
        "CONCLAVE_JWT_ISSUER",
        "CONCLAVE_JWT_DEFAULT_AUDIENCE",
        "CONCLAVE_JWT_SIGNING_SECRET",
        "CONCLAVE_JWT_TTL_SECONDS",
        "CONCLAVE_FELDERA_ENABLED",
        "CONCLAVE_FELDERA_BASE_URL",
        "CONCLAVE_FELDERA_PIPELINE_PREFIX",
        "CONCLAVE_FELDERA_READINESS_PROBE",
        "CONCLAVE_FELDERA_API_KEY",
        "CONCLAVE_FELDERA_COMPILE_PROFILE",
        "CONCLAVE_FELDERA_AUTO_START",
        "CONCLAVE_FELDERA_START_INITIAL",
    ];
}
