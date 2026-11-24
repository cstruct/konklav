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
    let (listen, database, telemetry, tokens, browser, control, feed, mfa) = loaded;
    assert_eq!(listen.listen.control, "0.0.0.0:9000".parse().unwrap());
    assert_eq!(listen.listen.subject, "127.0.0.1:8080".parse().unwrap());
    assert_eq!(database.database.password, "from-secrets");
    assert_eq!(database.database.max_connections, 10, "default applies");
    assert_eq!(telemetry.telemetry.logs.level, "info");
    assert!(!telemetry.telemetry.traces.enabled);
    assert_eq!(tokens.tokens.access_ttl_seconds, 900, "default applies");
    assert_eq!(tokens.tokens.published_key_files, Vec::<String>::new());
    assert_eq!(browser.browser, None);
    assert_eq!(control.bootstrap_token().as_deref(), Some("t"));
    assert!(control.bootstrap_expiry().is_err(), "`t` is too short");
    assert_eq!(
        control.batches(),
        konklav_server::batch_api::BatchLimits::DEFAULT,
        "default applies"
    );
    assert_eq!(
        feed.retention(),
        chrono::Duration::hours(168),
        "default applies"
    );
    assert_eq!(feed.history_retention(), None, "history is off by default");
    assert_eq!(mfa.mfa, None);
}

// r[verify history.config]
#[test]
fn history_is_off_unless_enabled() {
    let files = Files::new("history");
    let secrets = files.write("s.styx", SECRETS);
    for (section, retention) in [
        ("history {retention_days 14}", None),
        ("history {enabled true}", Some(90)),
        ("history {enabled true, retention_days 14}", Some(14)),
    ] {
        let (_, _, _, _, _, _, feed, _) = load(
            &files.write("c.styx", &format!("{CONFIG}{section}\n")),
            &secrets,
            &[],
        )
        .unwrap();
        assert_eq!(
            feed.history_retention(),
            retention.map(chrono::Duration::days),
            "{section}"
        );
    }
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
    let (_, database, _, tokens, mut browser, _, _, mfa) =
        load(&root.join("dev.styx"), &root.join("dev.secrets.styx"), &[]).unwrap();
    assert_eq!(database.database.port, 15432);
    // Served from the issuer, 127.0.0.1, where passkeys (for localhost)
    // can't work, so the page offers none and passkeys keep their origins.
    let page = konklav_server::login_page::LoginPage::configure(&tokens.tokens, &mut browser)
        .unwrap()
        .expect("the dev config turns the login page on");
    assert!(!page.passkeys);
    assert!(
        tokens
            .oidc_provider
            .as_ref()
            .is_some_and(|provider| provider.login_url.is_none()),
        "the dev config's OpenID provider hands off to the login page"
    );
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
    local_mfa_factors 0
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

    // r[verify federation.local-mfa]
    let undecided = public.replace("    local_mfa_factors 0\n", "");
    assert!(
        load(
            &files.write("undecided.styx", &undecided),
            &files.write("s.styx", &secrets),
            &[],
        )
        .is_err(),
        "local_mfa_factors has no default"
    );

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

// r[verify federation.github]
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
    local_mfa_factors 0
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
        ("kind saml", "kind must be `oidc` or `github`"),
        (
            "kind github\n    require_acr urn:hwk",
            "GitHub has no ID token or discovery, so `require_acr`",
        ),
        (
            "kind github\n    workloads true",
            "GitHub has no ID token or discovery, so `workloads`",
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
    let (.., browser, _, _, _) = load(
        &files.write("c.styx", &provider("kind github")),
        &files.write("s.styx", &secrets),
        &[],
    )
    .unwrap();
    let providers = konklav_server::federation::Providers::from_config(&browser).unwrap();
    let github = providers.get("ops").unwrap();
    assert!(matches!(
        &github.settings.protocol,
        konklav_server::federation::Protocol::GitHub(endpoints)
            if endpoints.api() == "https://ops.example/api/v3"
    ));
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
        konklav_server::oidc::OpenIdProvider::load(&config, &tokens.tokens.issuer, None).unwrap();
    assert_eq!(provider.jwk.alg, "ES256");
    assert_eq!(
        provider.jwk.x.as_deref(),
        Some("Y6_1EEzqCvOEimuWQdUYPZi0Vo88sqdVzRqcBdc1zB4")
    );
    assert_eq!(
        provider.jwks_uri,
        "https://auth.example/.well-known/jwks.json"
    );
    assert!(provider.claims_hook.is_none());
    assert!(
        !provider.logout_private_addresses,
        "logout tokens go to public addresses unless configured"
    );
    let private = format!(
        "{CONFIG}oidc_provider {{\n    id_token_key_file \"{}\"\n    login_url \"https://login.example/\"\n    \
         backchannel_logout_private_addresses true\n}}\n",
        key.display()
    );
    let (_, _, _, tokens, ..) = load(
        &files.write("private.styx", &private),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap();
    let config = tokens.oidc_provider.unwrap();
    let provider =
        konklav_server::oidc::OpenIdProvider::load(&config, &tokens.tokens.issuer, None).unwrap();
    assert!(provider.logout_private_addresses);

    let hooked = |scopes: &str| {
        format!(
            "{CONFIG}oidc_provider {{\n    id_token_key_file \"{}\"\n    login_url \"https://login.example/\"\n    \
             claims_hook {{\n        url \"https://profiles.example/claims\"\n        cache_ttl_seconds 60\n        \
             scopes {{\n            {scopes}\n        }}\n    }}\n}}\n",
            key.display()
        )
    };
    let load_hook = |scopes: &str| {
        let (_, _, _, tokens, ..) = load(
            &files.write("hook.styx", &hooked(scopes)),
            &files.write("s.styx", SECRETS),
            &[],
        )
        .unwrap();
        let config = tokens.oidc_provider.unwrap();
        konklav_server::oidc::OpenIdProvider::load(&config, &tokens.tokens.issuer, None)
            .map(|provider| provider.claims_hook.is_some())
    };
    assert_eq!(load_hook("profile (name given_name)"), Ok(true));
    assert!(
        load_hook("profile (name email)").is_err(),
        "a hook can't supply Konklav's own claims"
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
    local_mfa_factors 0
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
            batch_max_operations: 100,
            batch_key_seconds: 600,
            batch_key_max_seconds: 3600,
            metadata_max_bytes: 16384,
        }),
        access_requests: None,
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

const DEV_SECRETS: &str = concat!(
    "database {password x}\n",
    "control {bootstrap_token konklav-dev-control-token-0123456789}\n",
    "mfa {totp_keys ({id dev, key \"ZGV2LW9ubHktdG90cC1lbmNyeXB0aW9uLWtleS0zMmI=\"})}\n",
);

/// What `serve` and `check-config` answer for these files.
fn check_deployment(files: &Files, config: &str, secrets: &str) -> Result<(), String> {
    let (_, _, _, tokens, browser, control, _, mfa) = load(
        &files.write("c.styx", config),
        &files.write("s.styx", secrets),
        &[],
    )
    .unwrap();
    config::check_deployment(&tokens, &browser, &control, &mfa)
}

// r[verify platform.config.published-secrets]
#[test]
fn published_secrets_are_refused_outside_development() {
    let files = Files::new("published-secrets");
    let error = check_deployment(&files, CONFIG, DEV_SECRETS).unwrap_err();
    for setting in ["control.bootstrap_token", "mfa.totp_keys `dev`"] {
        assert!(error.contains(setting), "missing {setting} in:\n{error}");
    }
    assert!(error.contains("generate a new one"), "{error}");

    let example = concat!(
        "database {password x}\n",
        "control {bootstrap_token example-bootstrap-token-0123456789abcdef}\n",
        "mfa {totp_keys ({id new, key \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"} ",
        "{id old, key \"ZXhhbXBsZS1vbmx5LXRvdHAtZW5jcnlwdGlvbi1rZXk=\"})}\n",
    );
    let error = check_deployment(&files, CONFIG, example).unwrap_err();
    assert!(error.contains("control.bootstrap_token"), "{error}");
    assert!(error.contains("mfa.totp_keys `old`"), "{error}");
    assert!(!error.contains("`new`"), "{error}");

    let own = DEV_SECRETS
        .replace("konklav-dev-control-token-0123456789", &"a".repeat(32))
        .replace(
            "ZGV2LW9ubHktdG90cC1lbmNyeXB0aW9uLWtleS0zMmI=",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        );
    assert_eq!(check_deployment(&files, CONFIG, &own), Ok(()));

    // Development configurations keep working with them.
    let local = CONFIG.replace("https://auth.example", "http://127.0.0.1:8080");
    assert_eq!(check_deployment(&files, &local, DEV_SECRETS), Ok(()));
    let insecure = format!(
        "{CONFIG}browser {{allowed_origins (\"http://app.test\"), secure_cookies false}}\n"
    );
    assert_eq!(check_deployment(&files, &insecure, DEV_SECRETS), Ok(()));
    let secure = format!("{CONFIG}browser {{allowed_origins (\"https://app.example\")}}\n");
    assert!(check_deployment(&files, &secure, DEV_SECRETS).is_err());
}

#[test]
fn the_dev_and_example_configs_are_development_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (config, secrets) in [
        ("config/dev.styx", "config/dev.secrets.styx"),
        (
            "examples/notes-app/konklav/config.styx",
            "examples/notes-app/konklav/secrets.styx",
        ),
    ] {
        let (_, _, _, tokens, browser, control, _, mfa) =
            load(&root.join(config), &root.join(secrets), &[]).unwrap();
        assert_eq!(
            config::check_deployment(&tokens, &browser, &control, &mfa),
            Ok(()),
            "{config}"
        );
    }
}

// r[verify platform.config.https]
#[test]
fn the_issuer_and_claims_hook_must_use_https_outside_development() {
    let files = Files::new("https-urls");
    let hooked = |issuer: &str, hook: &str| {
        format!(
            "{}oidc_provider {{\n    id_token_key_file id.pem\n    login_url \"https://login.example/\"\n    \
             claims_hook {{\n        url \"{hook}\"\n        scopes {{\n            profile (name)\n        }}\n    }}\n}}\n",
            CONFIG.replace("https://auth.example", issuer)
        )
    };
    let check = |issuer: &str, hook: &str| check_deployment(&files, &hooked(issuer, hook), SECRETS);
    let secure = "https://profiles.example/claims";
    assert_eq!(check("https://auth.example", secure), Ok(()));
    // A hook beside the server needs no TLS.
    for local in ["http://127.0.0.1:9000/claims", "http://[::1]:9000/claims"] {
        assert_eq!(check("https://auth.example", local), Ok(()), "{local}");
    }

    let error = check("http://auth.example", secure).unwrap_err();
    assert!(
        error.contains("tokens.issuer must be an `https://` URL"),
        "{error}"
    );
    for hook in [
        "http://profiles.example/claims",
        "http://localhost.example/claims",
        "ftp://127.0.0.1/claims",
        "profiles.example/claims",
    ] {
        let error = check("https://auth.example", hook).unwrap_err();
        assert!(
            error.contains("oidc_provider.claims_hook.url must be"),
            "{hook}: {error}"
        );
    }
    let both = check("http://auth.example", "http://profiles.example/claims").unwrap_err();
    assert_eq!(both.lines().count(), 2, "{both}");

    // Development: plain HTTP on this machine, or cookies without `Secure`.
    assert_eq!(
        check("http://localhost:8000", "http://profiles.test/claims"),
        Ok(())
    );
    let insecure = format!(
        "{}browser {{allowed_origins (\"http://app.test\"), secure_cookies false}}\n",
        hooked(
            "http://host.docker.internal:8080",
            "http://profiles.test/claims"
        )
    );
    assert_eq!(check_deployment(&files, &insecure, SECRETS), Ok(()));
}

const LOGIN_PAGE_ID_TOKEN_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUoptOOQL2DZqHV4Q
GpDMUYd6rsbhOjYqdxTU6xh4DmahRANCAARjr/UQTOoK84SKa5ZB1Rg9mLRWjzyy
p1XNGpwF1zXMHj8NrRZRBsdiy2jZvNVSLlPqzmK3P4YLDAtSoKNCeXst
-----END PRIVATE KEY-----
";

// r[verify oidc.provider.login-page]
#[test]
fn the_login_page_is_the_login_url_unless_one_is_configured() {
    use konklav_server::login_page::LoginPage;

    let files = Files::new("login-page");
    let key = files.write("id-token.pem", LOGIN_PAGE_ID_TOKEN_KEY);
    let public = format!(
        r#"{CONFIG}
browser {{
    allowed_origins ("https://app.example")
}}
passkeys {{
    rp_id example
    rp_name Example
    origins ("https://app.example")
}}
identity_providers ({{
    id ops
    name "Ops directory"
    issuer "https://ops.example"
    client_id prod-eu
    redirect_uri "https://auth.example/v1/login/oidc/ops/callback"
    return_urls ("https://app.example/")
    local_mfa_factors 0
}})
oidc_provider {{
    id_token_key_file "{}"
}}
login_page {{
    title "Example Corp"
}}
"#,
        key.display()
    );
    let secrets =
        format!("{SECRETS}identity_provider_secrets ({{provider ops, client_secret shh}})\n");
    let (_, _, _, tokens, mut browser, ..) = load(
        &files.write("c.styx", &public),
        &files.write("s.styx", &secrets),
        &[],
    )
    .unwrap();
    let page = LoginPage::configure(&tokens.tokens, &mut browser)
        .unwrap()
        .expect("the page is configured");
    assert_eq!(page.title, "Example Corp");
    assert_eq!(page.return_to, "https://auth.example/login/");
    assert!(page.passkeys);
    assert_eq!(page.identity_providers.len(), 1);
    assert_eq!(page.identity_providers[0].id, "ops");
    assert_eq!(page.identity_providers[0].name, "Ops directory");

    // The page, served from the issuer's origin, may use browser sign-in
    // and passkeys, and identity providers may return to it, after the
    // URLs configured before it.
    let allowed = &browser.browser.as_ref().unwrap().allowed_origins;
    assert_eq!(allowed, &["https://app.example", "https://auth.example"]);
    assert_eq!(
        browser.passkeys.as_ref().unwrap().origins,
        ["https://app.example", "https://auth.example"]
    );
    assert_eq!(
        browser.identity_providers[0].return_urls,
        ["https://app.example/", "https://auth.example/login/"]
    );
    assert!(konklav_server::federation::Providers::from_config(&browser).is_ok());
    assert!(
        konklav_server::passkeys::Verifier::from_config(
            browser.passkeys.as_ref().unwrap(),
            browser.browser.as_ref()
        )
        .is_ok()
    );

    let config = tokens.oidc_provider.as_ref().unwrap();
    let provider = konklav_server::oidc::OpenIdProvider::load(
        config,
        &tokens.tokens.issuer,
        Some(&page.return_to),
    )
    .unwrap();
    assert_eq!(provider.login_url, "https://auth.example/login/");

    // A configured login URL wins.
    let mut configured = config.clone();
    configured.login_url = Some("https://login.example/".into());
    let provider = konklav_server::oidc::OpenIdProvider::load(
        &configured,
        &tokens.tokens.issuer,
        Some(&page.return_to),
    )
    .unwrap();
    assert_eq!(provider.login_url, "https://login.example/");

    // Without the page, there is nowhere to send people.
    let refused =
        konklav_server::oidc::OpenIdProvider::load(config, &tokens.tokens.issuer, None).err();
    assert!(
        refused.is_some_and(|error| error.contains("login_url")),
        "a login URL is required without the login page"
    );
}

// r[verify oidc.provider.login-page]
#[test]
fn the_login_page_needs_browser_sign_in() {
    use konklav_server::login_page::LoginPage;

    let files = Files::new("login-page-without-browser");
    let (_, _, _, tokens, mut browser, ..) = load(
        &files.write(
            "c.styx",
            &format!("{CONFIG}login_page {{\n    enabled true\n}}\n"),
        ),
        &files.write("s.styx", SECRETS),
        &[],
    )
    .unwrap();
    assert!(browser.login_page.is_some());
    let refused = LoginPage::configure(&tokens.tokens, &mut browser).unwrap_err();
    assert!(refused.contains("browser"), "{refused}");

    for off in [
        String::new(),
        "login_page {\n    enabled false\n}\n".to_owned(),
    ] {
        let (_, _, _, tokens, mut browser, ..) = load(
            &files.write("off.styx", &format!("{CONFIG}{off}")),
            &files.write("s.styx", SECRETS),
            &[],
        )
        .unwrap();
        assert!(
            LoginPage::configure(&tokens.tokens, &mut browser)
                .unwrap()
                .is_none(),
            "{off}"
        );
    }
}
