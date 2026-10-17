use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::{self, BuildError};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

/// A pool of async Postgres connections.
pub type Pool = deadpool::Pool<AsyncPgConnection>;

/// How to reach the database.
#[derive(Clone)]
pub struct ConnectOptions {
    /// A libpq-style connection URL. It usually contains a password, so it is
    /// never logged.
    pub url: String,
    pub max_connections: usize,
}

impl std::fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectOptions")
            .field("url", &"<redacted>")
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("could not build the connection pool: {0}")]
    Build(#[from] BuildError),
    #[error("could not get a connection from the pool: {0}")]
    Checkout(#[from] deadpool::PoolError),
    #[error("database query failed: {0}")]
    Query(#[from] diesel::result::Error),
}

// r[impl platform.storage.postgres]
/// Builds a connection pool. Connections are opened lazily, so this succeeds
/// even while the database is unreachable; use [`ping`] to check.
pub fn connect(options: &ConnectOptions) -> Result<Pool, PoolError> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&options.url);
    Ok(Pool::builder(manager)
        .max_size(options.max_connections)
        .build()?)
}

/// Checks that a pooled connection can run a query.
pub async fn ping(pool: &Pool) -> Result<(), PoolError> {
    let mut conn = pool.get().await?;
    diesel::sql_query("select 1").execute(&mut conn).await?;
    Ok(())
}
