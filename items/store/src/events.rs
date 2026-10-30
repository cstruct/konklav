//! The change-feed outbox.

use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::Cursor;

use crate::schema::{event, feed_watermark};

/// Appends an event and returns its cursor. Call it inside the transaction
/// that makes the change, so the change and its event commit together.
// r[impl platform.storage.transactional-events]
// r[impl feed.outbox]
pub async fn append(
    conn: &mut AsyncPgConnection,
    kind: &str,
    payload: serde_json::Value,
) -> QueryResult<Cursor> {
    diesel::insert_into(event::table)
        .values((event::kind.eq(kind), event::payload.eq(payload)))
        .returning(event::cursor)
        .get_result::<i64>(conn)
        .await
        .map(Cursor::new)
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = event)]
pub struct Event {
    pub cursor: i64,
    pub kind: String,
    pub payload: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Events after `after`, oldest first.
pub async fn after(
    conn: &mut AsyncPgConnection,
    after: Cursor,
    limit: i64,
) -> QueryResult<Vec<Event>> {
    event::table
        .filter(event::cursor.gt(after.get()))
        .order(event::cursor.asc())
        .limit(limit)
        .select(Event::as_select())
        .load(conn)
        .await
}

/// The cursor of the last event written by the current transaction, if any.
/// Triggers append events too, so this is how a write learns the cursor to
/// report. Call it inside the writing transaction.
// r[impl platform.idempotency.write-cursor]
pub async fn last_in_transaction(conn: &mut AsyncPgConnection) -> QueryResult<Option<Cursor>> {
    diesel::sql_query(
        "select max(cursor) as cursor from event where xmin = pg_current_xact_id()::xid",
    )
    .get_result::<LastCursor>(conn)
    .await
    .map(|row| row.cursor.map(Cursor::new))
}

#[derive(QueryableByName)]
struct LastCursor {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    cursor: Option<i64>,
}

/// The cursor of the newest event, or [`Cursor::START`] when there is none.
pub async fn head(conn: &mut AsyncPgConnection) -> QueryResult<Cursor> {
    event::table
        .select(diesel::dsl::max(event::cursor))
        .get_result::<Option<i64>>(conn)
        .await
        .map(|cursor| cursor.map_or(Cursor::START, Cursor::new))
}

/// The highest cursor retention has pruned. Resuming from below it would
/// miss events.
// r[impl feed.retention]
pub async fn pruned_through(conn: &mut AsyncPgConnection) -> QueryResult<Cursor> {
    feed_watermark::table
        .select(feed_watermark::pruned_through)
        .first::<i64>(conn)
        .await
        .map(Cursor::new)
}

/// Deletes up to `batch` of the oldest events created before `cutoff` and
/// advances the watermark past them. Returns how many it deleted.
pub async fn prune_before(
    conn: &mut AsyncPgConnection,
    cutoff: chrono::DateTime<chrono::Utc>,
    batch: i64,
) -> QueryResult<usize> {
    use diesel_async::AsyncConnection;
    conn.transaction(async |conn| {
        #[derive(QueryableByName)]
        struct Deleted {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            cursor: i64,
        }
        let deleted = diesel::sql_query(
            "delete from event where cursor in (
                 select cursor from event where created_at < $1 order by cursor limit $2
             ) returning cursor",
        )
        .bind::<diesel::sql_types::Timestamptz, _>(cutoff)
        .bind::<diesel::sql_types::BigInt, _>(batch)
        .get_results::<Deleted>(conn)
        .await?;
        if let Some(highest) = deleted.iter().map(|d| d.cursor).max() {
            diesel::update(feed_watermark::table)
                .filter(feed_watermark::pruned_through.lt(highest))
                .set(feed_watermark::pruned_through.eq(highest))
                .execute(conn)
                .await?;
        }
        Ok(deleted.len())
    })
    .await
}
