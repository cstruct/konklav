//! Conclave's Postgres schema, migrations, connection pool and repositories.
//!
//! Conclave owns its database exclusively. Every other software item reaches
//! it through this crate.

mod migrate;
mod pool;
pub mod schema;

pub use migrate::{MigrationError, pending_migrations, run_pending_migrations};
pub use pool::{ConnectOptions, Pool, PoolError, connect, ping};
