//! `jti`s of JWT bearer assertions already exchanged.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;
use crate::schema::bearer_assertion;

/// Records an assertion's `jti`. Returns false if the issuer's assertion
/// was already exchanged, so a replay is refused. Expired records are
/// pruned.
pub async fn record(
    conn: &mut AsyncPgConnection,
    issuer: &str,
    jti: &str,
    expires_at: DateTime<Utc>,
) -> StoreResult<bool> {
    diesel::delete(bearer_assertion::table.filter(bearer_assertion::expires_at.lt(Utc::now())))
        .execute(conn)
        .await?;
    let inserted = diesel::insert_into(bearer_assertion::table)
        .values((
            bearer_assertion::issuer.eq(issuer),
            bearer_assertion::jti.eq(jti),
            bearer_assertion::expires_at.eq(expires_at),
        ))
        .on_conflict_do_nothing()
        .execute(conn)
        .await?;
    Ok(inserted > 0)
}
