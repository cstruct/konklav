use diesel_async::AsyncMigrationHarness;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::{Pool, PoolError};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error(transparent)]
    Pool(#[from] PoolError),
    #[error("migration failed: {0}")]
    Migration(Box<dyn std::error::Error + Send + Sync>),
}

impl From<diesel_async::pooled_connection::deadpool::PoolError> for MigrationError {
    fn from(error: diesel_async::pooled_connection::deadpool::PoolError) -> Self {
        Self::Pool(error.into())
    }
}

/// Lists the embedded migrations that have not been applied yet, by name.
///
/// The harness blocks its thread while it runs, so this must be called from a
/// multi-threaded tokio runtime.
// r[impl platform.storage.forward-migrations]
pub async fn pending_migrations(pool: &Pool) -> Result<Vec<String>, MigrationError> {
    let conn = pool.get().await?;
    let mut harness = AsyncMigrationHarness::new(conn);
    let pending = harness
        .pending_migrations(MIGRATIONS)
        .map_err(MigrationError::Migration)?;
    Ok(pending.iter().map(|m| m.name().to_string()).collect())
}

/// Applies every pending embedded migration, in order, and returns their
/// versions.
///
/// Migrations are forward-only: there are no down migrations to revert.
/// Like [`pending_migrations`], this needs a multi-threaded tokio runtime.
pub async fn run_pending_migrations(pool: &Pool) -> Result<Vec<String>, MigrationError> {
    let conn = pool.get().await?;
    let mut harness = AsyncMigrationHarness::new(conn);
    let applied = harness
        .run_pending_migrations(MIGRATIONS)
        .map_err(MigrationError::Migration)?;
    Ok(applied.iter().map(ToString::to_string).collect())
}
