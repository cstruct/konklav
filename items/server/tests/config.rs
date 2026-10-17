use std::path::{Path, PathBuf};

use conclave_server::config::{self, ConfigError, MigrateContexts, ServeContexts, ServerContexts};
use ordna_core::ConfigContexts;
use ordna_core::ConfigLoadError;
use ordna_source_env::EnvSource;

const CONFIG: &str = r#"
listen {
    subject "127.0.0.1:8080"
    relying "127.0.0.1:8081"
    control "127.0.0.1:8082"
}
database {
    host localhost
    port 5432
    name conclave
    user conclave
}
tokens {
    issuer "https://auth.example"
    audience api
    signing_key_file "key.pem"
}
"#;

const SECRETS: &str =
    "database {\n    password from-secrets\n}\ncontrol {\n    bootstrap_token t\n}\n";

struct Files(PathBuf);

impl Files {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("conclave-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn env(vars: &[(&'static str, &'static str)]) -> EnvSource {
    EnvSource::from_vars(vars.iter().copied()).prefix(config::ENV_PREFIX)
}

fn load_as<X: ConfigContexts<ServerContexts>>(
    config: &Path,
    secrets: &Path,
    vars: &[(&'static str, &'static str)],
) -> Result<X, ConfigError> {
    config::load(config, secrets, env(vars))
}

fn load(
    config: &Path,
    secrets: &Path,
    vars: &[(&'static str, &'static str)],
) -> Result<ServeContexts, ConfigError> {
    load_as(config, secrets, vars)
}

// r[verify platform.config.layered]
#[test]
fn environment_overrides_the_config_file() {
    let files = Files::new("layered");
    let loaded = load(
        &files.write("c.styx", CONFIG),
        &files.write("s.styx", SECRETS),
        &[("CONCLAVE__LISTEN__CONTROL", "0.0.0.0:9000")],
    )
    .unwrap();
    let (listen, database, log, tokens, browser, control, feed, mfa) = loaded;
    assert_eq!(listen.listen.control, "0.0.0.0:9000".parse().unwrap());
    assert_eq!(listen.listen.subject, "127.0.0.1:8080".parse().unwrap());
    assert_eq!(database.database.password, "from-secrets");
    assert_eq!(database.database.max_connections, 10, "default applies");
    assert_eq!(log.filter(), None);
    assert_eq!(tokens.tokens.access_ttl_seconds, 900, "default applies");
    assert_eq!(tokens.tokens.published_key_files, Vec::<String>::new());
    assert_eq!(browser.browser, None);
    assert_eq!(control.control.bootstrap_token, "t");
    assert_eq!(
        feed.retention(),
        chrono::Duration::hours(168),
        "default applies"
    );
    assert_eq!(mfa.mfa, None);
}

// r[verify platform.config.secrets-separate]
#[test]
fn rejects_secrets_in_the_public_file() {
    let files = Files::new("secret-in-public");
    let public = CONFIG.replace(
        "    user conclave\n",
        "    user conclave\n    password leaked\n",
    );
    let error = load(
        &files.write("c.styx", &public),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap_err();
    assert!(error.to_string().contains("database.password"), "{error}");
}

#[test]
fn rejects_secrets_from_the_environment() {
    let files = Files::new("secret-in-env");
    let error = load(
        &files.write("c.styx", CONFIG),
        &files.write("s.styx", SECRETS),
        &[("CONCLAVE__DATABASE__PASSWORD", "from-env")],
    )
    .unwrap_err();
    assert!(error.to_string().contains("database.password"), "{error}");
}

#[test]
fn rejects_public_values_in_the_secrets_file() {
    let files = Files::new("public-in-secrets");
    let error = load(
        &files.write("c.styx", CONFIG),
        &files.write("s.styx", "database {\n    password x\n    port 1\n}\n"),
        &[],
    )
    .unwrap_err();
    assert!(error.to_string().contains("database.port"), "{error}");
}

// r[verify platform.config.report-all-errors]
#[test]
fn reports_every_problem_at_once() {
    let files = Files::new("all-errors");
    let config = CONFIG.replace("database {", "unknown_key 1\ndatabase {");
    let error = load(
        &files.write("c.styx", &config),
        &files.write("s.styx", SECRETS),
        &[
            ("CONCLAVE__DATABASE__PASSWORD", "from-env"),
            ("CONCLAVE__LISTEN__NOPE", "1"),
        ],
    )
    .unwrap_err();
    let ConfigLoadError::Violations(_) = error.inner() else {
        panic!("expected violations, got {error}");
    };
    let report = error.to_string();
    for expected in ["unknown_key", "listen.nope", "database.password"] {
        assert!(
            report.contains(expected),
            "missing {expected} in:\n{report}"
        );
    }
}

#[test]
fn the_dev_config_loads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
    let (_, database, _, _, browser, _, _, mfa) =
        load(&root.join("dev.styx"), &root.join("dev.secrets.styx"), &[]).unwrap();
    assert_eq!(database.database.port, 55432);
    assert!(!browser.browser.unwrap().secure_cookies);
    assert_eq!(mfa.mfa.unwrap().totp_keys.len(), 1);
}

#[test]
fn reports_values_that_do_not_decode() {
    let files = Files::new("decode");
    let error = load(
        &files.write("c.styx", &CONFIG.replace("port 5432", "port not-a-port")),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap_err();
    assert!(error.to_string().contains("not-a-port"), "{error}");
}

const DATABASE_ONLY: &str =
    "database {\n    host localhost\n    port 5432\n    name conclave\n    user conclave\n}\n";

#[test]
fn migrating_does_not_need_listeners() {
    let files = Files::new("migrate-no-listen");
    let (database, _) = load_as::<MigrateContexts>(
        &files.write("c.styx", DATABASE_ONLY),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap();
    assert_eq!(database.database.host, "localhost");
}

#[test]
fn serving_needs_listeners() {
    let files = Files::new("serve-no-listen");
    let error = load(
        &files.write("c.styx", DATABASE_ONLY),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap_err();
    assert!(error.to_string().contains("listen"), "{error}");
}

#[test]
fn migrating_still_rejects_unknown_keys() {
    let files = Files::new("migrate-typo");
    let error = load_as::<MigrateContexts>(
        &files.write(
            "c.styx",
            &format!("{DATABASE_ONLY}listen {{\n    subjct \"127.0.0.1:1\"\n}}\n"),
        ),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap_err();
    assert!(error.to_string().contains("listen.subjct"), "{error}");
}
