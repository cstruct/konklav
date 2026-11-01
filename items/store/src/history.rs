//! History: past versions of the rows compilation and decision explanations
//! read, so a decision can be explained as of a past time.
//!
//! Triggers record the versions while history is enabled (see the
//! `add_history` migration). Reading the past goes through [`shadow`],
//! which makes the ordinary repository functions see the state as of a
//! time for the rest of a transaction.

use chrono::{DateTime, Utc};
use diesel::sql_types::{BigInt, Nullable, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;

/// How far back history reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    /// When history was enabled. Nothing before is recorded.
    pub enabled_at: DateTime<Utc>,
    /// How long a version is kept after it stopped being current.
    pub retention: chrono::Duration,
}

impl Status {
    /// The earliest time history can answer for at `now`: when it was
    /// enabled, or `retention` ago, whichever is later.
    #[must_use]
    pub fn horizon(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        self.enabled_at.max(now - self.retention)
    }
}

/// Enables history with `retention`, or disables it when `None`. Enabling
/// an already enabled history only changes its retention; disabling
/// discards what was recorded.
// r[impl history.record]
// r[impl history.disabled]
pub async fn configure(
    conn: &mut AsyncPgConnection,
    retention: Option<chrono::Duration>,
) -> StoreResult<()> {
    diesel::sql_query("select history_configure(make_interval(secs => $1))")
        .bind::<Nullable<BigInt>, _>(retention.map(|r| r.num_seconds()))
        .execute(conn)
        .await?;
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct Row {
    #[diesel(sql_type = Nullable<Timestamptz>)]
    enabled_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<BigInt>)]
    retention: Option<i64>,
}

/// How far back history reaches, or `None` when it is disabled.
pub async fn status(conn: &mut AsyncPgConnection) -> StoreResult<Option<Status>> {
    let row = diesel::sql_query(
        "select enabled_at, extract(epoch from retention)::bigint as retention from history_setting",
    )
    .get_result::<Row>(conn)
    .await?;
    Ok(row
        .enabled_at
        .zip(row.retention)
        .map(|(enabled_at, retention)| Status {
            enabled_at,
            retention: chrono::Duration::seconds(retention),
        }))
}

/// Makes the rest of the current transaction read every versioned table
/// as of `at`: temporary tables of the same names, holding the versions
/// current then, shadow the live ones until the transaction ends. Call it
/// inside a repeatable-read transaction that writes nothing, and check
/// `at` against [`Status::horizon`] first.
// r[impl history.as-of]
pub async fn shadow(conn: &mut AsyncPgConnection, at: DateTime<Utc>) -> StoreResult<()> {
    diesel::sql_query("select history_shadow($1)")
        .bind::<Timestamptz, _>(at)
        .execute(conn)
        .await?;
    Ok(())
}
