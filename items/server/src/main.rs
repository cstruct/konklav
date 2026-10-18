use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use konklav_server::AppState;
use konklav_server::AuthContext;
use konklav_server::config::{
    self, BrowserConfig, ControlConfig, DatabaseConfig, FeedConfig, ListenConfig, LogConfig,
    MfaConfig, MigrateContexts, ServeContexts, ServerContexts, TokensConfig,
};
use konklav_server::feed::FeedHub;
use konklav_server::keys::ConfiguredKeys;
use konklav_server::serve::{BoundServer, shutdown_signal};
use ordna_core::ConfigContexts;
use std::path::Path;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// The Konklav identity and access server.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The public configuration file (Styx).
    #[arg(long, env = "KONKLAV_CONFIG")]
    config: PathBuf,
    /// The secrets configuration file (Styx). Only secret values may be set
    /// here, and secret values may only be set here.
    #[arg(long, env = "KONKLAV_SECRETS")]
    secrets: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the HTTP surfaces.
    Serve,
    /// Apply pending database migrations, then exit.
    Migrate,
    /// Load and validate the configuration, then exit.
    CheckConfig,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve => match load::<ServeContexts>(&cli) {
            Ok((listen, database, log, tokens, browser, control, feed, mfa)) => {
                init_tracing(&log);
                serve(listen, database, tokens, browser, control, feed, mfa).await
            }
            Err(code) => return code,
        },
        Command::Migrate => match load::<MigrateContexts>(&cli) {
            Ok((database, log)) => {
                init_tracing(&log);
                migrate(database).await
            }
            Err(code) => return code,
        },
        // Validates what `serve` needs, which is every context.
        Command::CheckConfig => match load::<ServeContexts>(&cli) {
            Ok(_) => {
                println!("configuration is valid");
                return ExitCode::SUCCESS;
            }
            Err(code) => return code,
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn load<X: ConfigContexts<ServerContexts>>(cli: &Cli) -> Result<X, ExitCode> {
    config::load(&cli.config, &cli.secrets, config::process_env()).map_err(|error| {
        eprintln!("{error}");
        ExitCode::FAILURE
    })
}

async fn migrate(config: DatabaseConfig) -> Result<(), Box<dyn std::error::Error>> {
    let pool = konklav_store::connect(&config.database.connect_options())?;
    let applied = konklav_store::run_pending_migrations(&pool).await?;
    if applied.is_empty() {
        tracing::info!("no pending migrations");
    }
    for version in applied {
        tracing::info!(%version, "applied migration");
    }
    Ok(())
}

async fn serve(
    listen: ListenConfig,
    database: DatabaseConfig,
    tokens: TokensConfig,
    browser: BrowserConfig,
    control: ControlConfig,
    feed: FeedConfig,
    mfa: MfaConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = tokens
        .oidc_provider
        .as_ref()
        .map(|config| konklav_server::oidc::OpenIdProvider::load(config, &tokens.tokens.issuer))
        .transpose()?;
    let pacing = konklav_server::pacing::Pacing {
        floor: tokens.pacing_floor(),
        jitter: tokens.pacing_jitter(),
    };
    let tokens = tokens.tokens;
    let keys = ConfiguredKeys::load(
        Path::new(&tokens.signing_key_file),
        &tokens.published_key_files,
    )?;
    let pool = konklav_store::connect(&database.database.connect_options())?;
    match konklav_store::pending_migrations(&pool).await {
        Ok(pending) if !pending.is_empty() => tracing::warn!(
            count = pending.len(),
            "migrations are pending; readiness will fail until `migrate` runs"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "could not check migrations at startup"),
    }
    match pool.get().await {
        Ok(mut conn) => keys.sync(&mut conn).await?,
        Err(error) => tracing::warn!(%error, "could not publish signing keys at startup"),
    }
    let mut auth = AuthContext::new(&tokens, browser.browser.as_ref(), &control, keys.signer);
    if let Some(mfa) = &mfa.mfa {
        auth.secrets = konklav_authn::SecretBox::new(
            mfa.totp_keys
                .iter()
                .map(|key| (key.id.as_str(), key.key.as_str())),
        )?;
    }
    auth.pacing = pacing;
    auth.oidc = oidc;
    auth.identity_providers = konklav_server::federation::Providers::from_config(&browser)?;
    auth.passkeys = browser
        .passkeys
        .as_ref()
        .map(|passkeys| {
            konklav_server::passkeys::Verifier::from_config(passkeys, browser.browser.as_ref())
        })
        .transpose()?;
    let hub = Arc::new(FeedHub::new(feed.poll_interval()));
    tokio::spawn(konklav_server::feed::listen(
        database.database.connect_options().url,
        hub.clone(),
    ));
    tokio::spawn(konklav_server::feed::prune(pool.clone(), feed.retention()));
    let state = AppState {
        pool,
        auth: Arc::new(auth),
        feed: hub,
    };
    tokio::spawn(konklav_server::oidc::deliver_logouts_forever(state.clone()));
    tokio::spawn(konklav_server::peering::sync_forever(state.clone()));
    let server = BoundServer::bind(&listen.listen, state).await?;
    server.run(shutdown_signal()).await?;
    Ok(())
}

fn init_tracing(config: &LogConfig) {
    let filter = std::env::var("RUST_LOG")
        .ok()
        .or_else(|| config.filter().map(str::to_owned))
        .unwrap_or_else(|| "info".to_owned());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .init();
}
