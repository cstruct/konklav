//! `jti`s of DPoP proofs Konklav accepted, per key, until the proofs are too
//! old to pass the freshness check.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;
use crate::schema::dpop_proof;

/// Records a proof's `jti` for its key. Returns false if the key already
/// used it, so a replayed proof is refused. The sweeper prunes expired
/// records.
// r[impl token.dpop.replay]
pub async fn record(
    conn: &mut AsyncPgConnection,
    jkt: &str,
    jti: &str,
    expires_at: DateTime<Utc>,
) -> StoreResult<bool> {
    let inserted = diesel::insert_into(dpop_proof::table)
        .values((
            dpop_proof::jkt.eq(jkt),
            dpop_proof::jti.eq(jti),
            dpop_proof::expires_at.eq(expires_at),
        ))
        .on_conflict_do_nothing()
        .execute(conn)
        .await?;
    Ok(inserted > 0)
}
