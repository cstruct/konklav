use std::path::{Path, PathBuf};

use konklav_server::config::{self, ConfigError, MigrateContexts, ServeContexts, ServerContexts};
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
    name konklav
    user konklav
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
            std::env::temp_dir().join(format!("konklav-config-{name}-{}", std::process::id()));
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
        &[("KONKLAV__LISTEN__CONTROL", "0.0.0.0:9000")],
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
    assert_eq!(control.bootstrap_token().as_deref(), Some("t"));
    assert!(control.bootstrap_expiry().is_err(), "`t` is too short");
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
        "    user konklav\n",
        "    user konklav\n    password leaked\n",
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
        &[("KONKLAV__DATABASE__PASSWORD", "from-env")],
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
            ("KONKLAV__DATABASE__PASSWORD", "from-env"),
            ("KONKLAV__LISTEN__NOPE", "1"),
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
    let passkeys = browser.passkeys.as_ref().unwrap();
    assert!(
        konklav_server::passkeys::Verifier::from_config(passkeys, browser.browser.as_ref()).is_ok()
    );
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
    "database {\n    host localhost\n    port 5432\n    name konklav\n    user konklav\n}\n";

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

// r[verify federation.idp.config]
#[test]
fn identity_providers_load_with_secrets_from_the_secrets_file() {
    let files = Files::new("identity-providers");
    let public = format!(
        r#"{CONFIG}
browser {{
    allowed_origins ("https://app.example")
}}
identity_providers ({{
    id ops
    issuer "https://ops.example"
    client_id prod-eu
    redirect_uri "https://auth.example/v1/login/oidc/ops/callback"
    return_urls ("https://app.example/")
    methods ({{from hwk, to hwk}})
    require_acr "urn:hwk"
    session_lifetime_seconds 3600
}})
"#
    );
    let secrets =
        format!("{SECRETS}identity_provider_secrets ({{provider ops, client_secret shh}})\n");
    let (.., browser, _, _, _) = load(
        &files.write("c.styx", &public),
        &files.write("s.styx", &secrets),
        &[],
    )
    .unwrap();
    assert_eq!(browser.identity_providers.len(), 1);
    assert_eq!(
        browser.identity_providers[0].require_acr.as_deref(),
        Some("urn:hwk")
    );
    assert_eq!(browser.identity_provider_secrets[0].client_secret, "shh");
    assert!(konklav_server::federation::Providers::from_config(&browser).is_ok());

    let misplaced = load(
        &files.write(
            "c.styx",
            &format!("{public}identity_provider_secrets ({{provider ops, client_secret shh}})\n"),
        ),
        &files.write("s.styx", SECRETS),
        &[],
    );
    assert!(misplaced.is_err(), "client secrets only load from secrets");

    let (.., browser, _, _, _) = load(
        &files.write("c.styx", &public),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap();
    let missing = konklav_server::federation::Providers::from_config(&browser).err();
    assert_eq!(
        missing.as_deref(),
        Some("identity provider `ops` has no client secret")
    );
}

#[test]
fn malformed_provisioning_and_grants_are_refused() {
    let files = Files::new("identity-provider-rules");
    let provider = |extra: &str| {
        format!(
            r#"{CONFIG}
identity_providers ({{
    id ops
    issuer "https://ops.example"
    client_id prod-eu
    redirect_uri "https://auth.example/v1/login/oidc/ops/callback"
    return_urls ("https://app.example/")
    {extra}
}})
"#
        )
    };
    let secrets =
        format!("{SECRETS}identity_provider_secrets ({{provider ops, client_secret shh}})\n");
    for (extra, expected) in [
        (
            "provisioning maybe",
            "provisioning must be `link` or `create`",
        ),
        (
            "grants ({claim groups, global_role operator})",
            "needs exactly one of equals and contains",
        ),
        (
            "grants ({claim groups, contains sre, global_role operator, tenant root})",
            "needs either global_role, or tenant",
        ),
    ] {
        let (.., browser, _, _, _) = load(
            &files.write("c.styx", &provider(extra)),
            &files.write("s.styx", &secrets),
            &[],
        )
        .unwrap();
        let error = konklav_server::federation::Providers::from_config(&browser)
            .err()
            .unwrap_or_default();
        assert!(error.contains(expected), "{extra}: {error}");
    }
    let (.., browser, _, _, _) = load(
        &files.write(
            "c.styx",
            &provider("provisioning create\n    grants ({claim groups, contains sre, global_role operator})"),
        ),
        &files.write("s.styx", &secrets),
        &[],
    )
    .unwrap();
    assert!(konklav_server::federation::Providers::from_config(&browser).is_ok());
}

// r[verify oidc.provider.algorithms]
#[test]
fn the_openid_provider_loads_its_id_token_key() {
    let files = Files::new("openid-provider");
    let key = files.write(
        "id-token.pem",
        "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUoptOOQL2DZqHV4Q
GpDMUYd6rsbhOjYqdxTU6xh4DmahRANCAARjr/UQTOoK84SKa5ZB1Rg9mLRWjzyy
p1XNGpwF1zXMHj8NrRZRBsdiy2jZvNVSLlPqzmK3P4YLDAtSoKNCeXst
-----END PRIVATE KEY-----
",
    );
    let public = format!(
        "{CONFIG}oidc_provider {{\n    id_token_key_file \"{}\"\n    login_url \"https://login.example/\"\n}}\n",
        key.display()
    );
    let (_, _, _, tokens, ..) = load(
        &files.write("c.styx", &public),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap();
    let config = tokens.oidc_provider.expect("the section loads");
    let provider =
        konklav_server::oidc::OpenIdProvider::load(&config, &tokens.tokens.issuer).unwrap();
    assert_eq!(provider.jwk.alg, "ES256");
    assert_eq!(
        provider.jwk.x,
        "Y6_1EEzqCvOEimuWQdUYPZi0Vo88sqdVzRqcBdc1zB4"
    );
    assert_eq!(
        provider.jwks_uri,
        "https://auth.example/.well-known/jwks.json"
    );
}

// r[verify federation.peer.pinning]
#[test]
fn pinned_keys_load_from_a_jwks_file() {
    let files = Files::new("pinned-keys");
    let jwks = files.write(
        "ops.jwks.json",
        r#"{"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "x": "Y6_1EEzqCvOEimuWQdUYPZi0Vo88sqdVzRqcBdc1zB4", "y": "Pw2tFlEGx2LLaNm81VIuU-rOYrc_hgsMC1Kgo0J5ey0"}]}"#,
    );
    let provider = |file: &str| {
        format!(
            r#"{CONFIG}
identity_providers ({{
    id ops
    issuer "https://ops.example"
    client_id prod-eu
    redirect_uri "https://auth.example/v1/login/oidc/ops/callback"
    return_urls ("https://app.example/")
    pinned_jwks_file "{file}"
    peering true
    workloads true
}})
"#
        )
    };
    let secrets =
        format!("{SECRETS}identity_provider_secrets ({{provider ops, client_secret shh}})\n");
    let (.., browser, _, _, _) = load(
        &files.write("c.styx", &provider(&jwks.display().to_string())),
        &files.write("s.styx", &secrets),
        &[],
    )
    .unwrap();
    let providers = konklav_server::federation::Providers::from_config(&browser).unwrap();
    let ops = providers.get("ops").unwrap();
    assert_eq!(ops.settings.pinned_keys.as_ref().unwrap().keys.len(), 1);
    assert!(ops.settings.peering && ops.settings.workloads);

    let (.., browser, _, _, _) = load(
        &files.write("c.styx", &provider("/nonexistent.json")),
        &files.write("s.styx", &secrets),
        &[],
    )
    .unwrap();
    assert!(konklav_server::federation::Providers::from_config(&browser).is_err());
}

// r[verify authn.passkey.origin]
#[test]
fn passkeys_default_to_the_browser_origins_within_their_relying_party_id() {
    let files = Files::new("passkeys");
    let public = |origins: &str| {
        format!(
            r#"{CONFIG}
browser {{
    allowed_origins ("https://app.example" "https://admin.app.example")
}}
passkeys {{
    rp_id app.example
    rp_name Konklav{origins}
}}
"#
        )
    };
    let (.., browser, _, _, _) = load(
        &files.write("c.styx", &public("")),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap();
    let passkeys = browser.passkeys.as_ref().unwrap();
    assert_eq!(passkeys.rp_id, "app.example");
    assert_eq!(passkeys.origins, Vec::<String>::new());
    assert!(
        konklav_server::passkeys::Verifier::from_config(passkeys, browser.browser.as_ref()).is_ok()
    );

    let (.., browser, _, _, _) = load(
        &files.write(
            "c.styx",
            &public("\n    origins (\"https://elsewhere.example\")"),
        ),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap();
    let error = konklav_server::passkeys::Verifier::from_config(
        browser.passkeys.as_ref().unwrap(),
        browser.browser.as_ref(),
    )
    .err()
    .unwrap();
    assert!(error.contains("not within relying party ID"), "{error}");
}

// r[verify platform.config.bootstrap-token]
#[test]
fn bootstrap_tokens_must_be_long_and_may_expire() {
    use konklav_server::config::{Control, ControlConfig};
    let config = |token: &str, expires: Option<&str>| ControlConfig {
        control: Some(Control {
            bootstrap_token: Some(token.to_owned()),
            bootstrap_token_expires_at: expires.map(str::to_owned),
        }),
    };
    assert!(config("short", None).bootstrap_expiry().is_err());
    let long = "a".repeat(32);
    assert_eq!(config(&long, None).bootstrap_expiry(), Ok(None));
    let expiry = config(&long, Some("2026-11-01T00:00:00Z"))
        .bootstrap_expiry()
        .unwrap()
        .unwrap();
    assert_eq!(expiry.to_rfc3339(), "2026-11-01T00:00:00+00:00");
    assert!(config(&long, Some("tomorrow")).bootstrap_expiry().is_err());
}
