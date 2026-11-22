//! `jti`s of `private_key_jwt` client assertions already used.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;
use crate::schema::client_assertion;

/// Records an assertion's `jti` until `accepted_until`, the last moment
/// the assertion passes validation, clock-skew leeway included. Returns
/// false if the client already used it, so a replayed assertion is refused.
/// The sweeper prunes records past that moment, never this function: an
/// assertion presented again must still find its own record.
pub async fn record(
    conn: &mut AsyncPgConnection,
    client: &str,
    jti: &str,
    accepted_until: DateTime<Utc>,
) -> StoreResult<bool> {
    let inserted = diesel::insert_into(client_assertion::table)
        .values((
            client_assertion::client_id.eq(client),
            client_assertion::jti.eq(jti),
            client_assertion::expires_at.eq(accepted_until),
        ))
        .on_conflict_do_nothing()
        .execute(conn)
        .await?;
    Ok(inserted > 0)
}
