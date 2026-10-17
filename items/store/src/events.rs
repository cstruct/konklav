//! The change-feed outbox.

use conclave_core::Cursor;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::schema::event;

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
