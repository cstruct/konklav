//! Test helpers shared by Konklav's software items.
//!
//! Tests get an isolated database each: [`TestDatabase`] creates a fresh,
//! fully migrated database on the development Postgres server and drops it
//! again afterwards. The server comes from `KONKLAV_TEST_DATABASE_URL`, or
//! `DATABASE_URL` as set by mise; start it with `mise run db:up`.
//!
//! Database tests must run on a multi-threaded runtime, because the migration
//! harness blocks its thread:
//!
//! ```ignore
//! #[tokio::test(flavor = "multi_thread")]
//! async fn stores_things() {
//!     let db = TestDatabase::new().await;
//!     // use db.pool() or db.url()
//! }
//! ```

mod dpop;

pub use dpop::DpopKey;

use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use konklav_store::{ConnectOptions, Pool};

const SERVER_URL_VARS: [&str; 2] = ["KONKLAV_TEST_DATABASE_URL", "DATABASE_URL"];

/// A freshly created and migrated database, dropped when this value is.
pub struct TestDatabase {
    name: String,
    admin_url: String,
    url: String,
    pool: Pool,
}

impl TestDatabase {
    /// Creates a uniquely named database and applies every migration.
    ///
    /// # Panics
    ///
    /// Panics when no server URL is configured, the server is unreachable, or
    /// migrations fail; a test cannot proceed in any of those cases.
    pub async fn new() -> Self {
        let admin_url = server_url();
        let name = format!("konklav_test_{}", uuid::Uuid::now_v7().simple());
        let url = with_database(&admin_url, &name);

        let mut admin = AsyncPgConnection::establish(&admin_url)
            .await
            .unwrap_or_else(|e| {
                panic!("cannot reach the test Postgres server (is `mise run db:up` running?): {e}")
            });
        diesel::sql_query(format!("create database \"{name}\""))
            .execute(&mut admin)
            .await
            .expect("create test database");

        let pool = konklav_store::connect(&ConnectOptions {
            url: url.clone(),
            max_connections: 4,
        })
        .expect("build test pool");
        konklav_store::run_pending_migrations(&pool)
            .await
            .expect("migrate test database");

        Self {
            name,
            admin_url,
            url,
            pool,
        }
    }

    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        // Drop runs outside async context, possibly inside a runtime that is
        // shutting down, so the cleanup gets its own thread and runtime.
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        let cleanup = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build cleanup runtime");
            runtime.block_on(async move {
                let mut admin = AsyncPgConnection::establish(&admin_url).await?;
                diesel::sql_query(format!("drop database if exists \"{name}\" with (force)"))
                    .execute(&mut admin)
                    .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            })
        });
        if let Ok(Err(error)) = cleanup.join() {
            eprintln!("could not drop test database {}: {error}", self.name);
        }
    }
}

fn server_url() -> String {
    SERVER_URL_VARS
        .iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| {
            panic!(
                "set {} to a Postgres server URL (mise sets DATABASE_URL; start it with `mise run db:up`)",
                SERVER_URL_VARS.join(" or ")
            )
        })
}

/// Replaces the database name in a `postgres://` URL, keeping any query.
fn with_database(url: &str, database: &str) -> String {
    let (base, query) = url
        .split_once('?')
        .map_or((url, None), |(b, q)| (b, Some(q)));
    let scheme_end = base.find("://").map_or(0, |i| i + 3);
    let host_part = match base[scheme_end..].find('/') {
        Some(slash) => &base[..scheme_end + slash],
        None => base,
    };
    match query {
        Some(query) => format!("{host_part}/{database}?{query}"),
        None => format!("{host_part}/{database}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_the_database_name() {
        assert_eq!(
            with_database("postgres://u:p@localhost:5432/konklav", "other"),
            "postgres://u:p@localhost:5432/other"
        );
    }

    #[test]
    fn adds_a_database_name_when_missing() {
        assert_eq!(
            with_database("postgres://u:p@localhost:5432", "other"),
            "postgres://u:p@localhost:5432/other"
        );
    }

    #[test]
    fn keeps_query_parameters() {
        assert_eq!(
            with_database("postgres://localhost/konklav?sslmode=disable", "other"),
            "postgres://localhost/other?sslmode=disable"
        );
    }
}
