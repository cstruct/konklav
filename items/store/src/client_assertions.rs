//! `jti`s of `private_key_jwt` client assertions already used.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;
use crate::schema::client_assertion;

/// Records an assertion's `jti`. Returns false if the client already used
/// it, so a replayed assertion is refused. Expired records are pruned.
pub async fn record(
    conn: &mut AsyncPgConnection,
    client: &str,
    jti: &str,
    expires_at: DateTime<Utc>,
) -> StoreResult<bool> {
    diesel::delete(client_assertion::table.filter(client_assertion::expires_at.lt(Utc::now())))
        .execute(conn)
        .await?;
    let inserted = diesel::insert_into(client_assertion::table)
        .values((
            client_assertion::client_id.eq(client),
            client_assertion::jti.eq(jti),
            client_assertion::expires_at.eq(expires_at),
        ))
        .on_conflict_do_nothing()
        .execute(conn)
        .await?;
    Ok(inserted > 0)
}
