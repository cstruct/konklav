//! Konklav's Postgres schema, migrations, connection pool and repositories.
//!
//! Konklav owns its database exclusively. Every other software item reaches
//! it through this crate. Repository functions take a connection so callers
//! can compose them inside one transaction.

pub mod backchannel;
pub mod bearer_assertions;
pub mod catalog;
pub mod challenges;
pub mod client_assertions;
pub mod compile_input;
pub mod credentials;
pub mod events;
pub mod history;
pub mod login_attempts;
pub mod memberships;
pub mod mfa;
mod migrate;
pub mod oidc_clients;
pub mod peer_cursors;
mod pool;
pub mod registered_scopes;
pub mod roles;
pub mod schema;
pub mod sessions;
pub mod shares;
pub mod signing_keys;
pub mod subjects;
pub mod sweep;
pub mod templates;
pub mod tenants;

pub use diesel_async::AsyncPgConnection as Connection;
pub use migrate::{MigrationError, pending_migrations, run_pending_migrations};
pub use pool::{Checkout, ConnectOptions, Pool, PoolError, connect, ping};

/// Errors from repository functions.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    /// A uniqueness or idempotency conflict, such as reusing an id with
    /// different content or an identifier that is already taken.
    #[error("conflict: {0}")]
    Conflict(String),
    /// A write to something only Konklav defines, such as a built-in role.
    #[error("reserved: {0}")]
    Reserved(String),
    #[error("database error: {0}")]
    Database(#[from] diesel::result::Error),
}

impl StoreError {
    fn from_unique_violation(error: diesel::result::Error, what: &str) -> Self {
        match error {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => Self::Conflict(format!("{what} already exists")),
            other => Self::Database(other),
        }
    }

    /// Maps constraint violations (foreign keys, checks, triggers) to
    /// conflicts carrying the database's message, and anything else to a
    /// database error.
    fn from_constraint(error: diesel::result::Error) -> Self {
        use diesel::result::DatabaseErrorKind as Kind;
        match error {
            diesel::result::Error::DatabaseError(
                Kind::UniqueViolation | Kind::ForeignKeyViolation | Kind::CheckViolation,
                info,
            ) => Self::Conflict(info.message().to_owned()),
            other => Self::Database(other),
        }
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
