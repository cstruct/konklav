//! Where this instance is in each peered identity provider's feed.

use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;
use crate::schema::peer_cursor;

pub async fn get(conn: &mut AsyncPgConnection, provider: &str) -> StoreResult<i64> {
    Ok(peer_cursor::table
        .find(provider)
        .select(peer_cursor::cursor)
        .first(conn)
        .await
        .optional()?
        .unwrap_or(0))
}

/// Moves the cursor forward; never back.
pub async fn advance(conn: &mut AsyncPgConnection, provider: &str, cursor: i64) -> StoreResult<()> {
    diesel::insert_into(peer_cursor::table)
        .values((
            peer_cursor::provider.eq(provider),
            peer_cursor::cursor.eq(cursor),
        ))
        .on_conflict(peer_cursor::provider)
        .do_update()
        .set((
            peer_cursor::cursor.eq(diesel::dsl::sql::<diesel::sql_types::BigInt>(
                "greatest(peer_cursor.cursor, excluded.cursor)",
            )),
            peer_cursor::updated_at.eq(diesel::dsl::now),
        ))
        .execute(conn)
        .await?;
    Ok(())
}
