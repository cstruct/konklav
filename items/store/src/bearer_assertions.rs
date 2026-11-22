//! `jti`s of JWT bearer assertions already exchanged.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;
use crate::schema::bearer_assertion;

/// Records an assertion's `jti` until `accepted_until`, the last moment
/// the assertion passes validation, clock-skew leeway included. Returns
/// false if the issuer's assertion was already exchanged, so a replay is
/// refused. The sweeper prunes records past that moment, never this
/// function: an assertion presented again must still find its own record.
pub async fn record(
    conn: &mut AsyncPgConnection,
    issuer: &str,
    jti: &str,
    accepted_until: DateTime<Utc>,
) -> StoreResult<bool> {
    let inserted = diesel::insert_into(bearer_assertion::table)
        .values((
            bearer_assertion::issuer.eq(issuer),
            bearer_assertion::jti.eq(jti),
            bearer_assertion::expires_at.eq(accepted_until),
        ))
        .on_conflict_do_nothing()
        .execute(conn)
        .await?;
    Ok(inserted > 0)
}
