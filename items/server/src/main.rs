use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use conclave_server::AppState;
use conclave_server::AuthContext;
use conclave_server::config::{
    self, BrowserConfig, ControlConfig, DatabaseConfig, FeedConfig, ListenConfig, LogConfig,
    MigrateContexts, ServeContexts, ServerContexts, TokensConfig,
};
use conclave_server::feed::FeedHub;
use conclave_server::keys::ConfiguredKeys;
use conclave_server::serve::{BoundServer, shutdown_signal};
use ordna_core::ConfigContexts;
use std::path::Path;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// The Conclave identity and access server.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The public configuration file (Styx).
    #[arg(long, env = "CONCLAVE_CONFIG")]
    config: PathBuf,
    /// The secrets configuration file (Styx). Only secret values may be set
    /// here, and secret values may only be set here.
    #[arg(long, env = "CONCLAVE_SECRETS")]
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
            Ok((listen, database, log, tokens, browser, control, feed)) => {
                init_tracing(&log);
                serve(listen, database, tokens, browser, control, feed).await
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
    let pool = conclave_store::connect(&config.database.connect_options())?;
    let applied = conclave_store::run_pending_migrations(&pool).await?;
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
) -> Result<(), Box<dyn std::error::Error>> {
    let tokens = tokens.tokens;
    let keys = ConfiguredKeys::load(
        Path::new(&tokens.signing_key_file),
        &tokens.published_key_files,
    )?;
    let pool = conclave_store::connect(&database.database.connect_options())?;
    match conclave_store::pending_migrations(&pool).await {
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
    let auth = AuthContext::new(
        &tokens,
        browser.browser.as_ref(),
        &control.control,
        keys.signer,
    );
    let hub = Arc::new(FeedHub::new(feed.poll_interval()));
    tokio::spawn(conclave_server::feed::listen(
        database.database.connect_options().url,
        hub.clone(),
    ));
    tokio::spawn(conclave_server::feed::prune(pool.clone(), feed.retention()));
    let state = AppState {
        pool,
        auth: Arc::new(auth),
        feed: hub,
    };
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
