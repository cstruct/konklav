//! Back-channel logout tokens waiting for delivery. Rows are queued by a
//! trigger when a client session is revoked.

use diesel::prelude::*;
use diesel::sql_types::{Int4, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::{SessionId, SubjectId};

use crate::StoreResult;

#[derive(Debug, Clone, QueryableByName)]
struct Row {
    #[diesel(sql_type = SqlUuid)]
    id: uuid::Uuid,
    #[diesel(sql_type = Text)]
    client_id: String,
    #[diesel(sql_type = SqlUuid)]
    session_id: uuid::Uuid,
    #[diesel(sql_type = SqlUuid)]
    subject_id: uuid::Uuid,
    #[diesel(sql_type = Int4)]
    attempts: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: uuid::Uuid,
    pub client_id: String,
    pub session_id: SessionId,
    pub subject_id: SubjectId,
    pub attempts: i32,
}

/// Takes up to `limit` due deliveries, leasing them for a minute so other
/// instances skip them meanwhile.
pub async fn lease(conn: &mut AsyncPgConnection, limit: i32) -> StoreResult<Vec<Pending>> {
    let rows: Vec<Row> = diesel::sql_query(
        "update backchannel_logout set next_attempt_at = now() + interval '1 minute'
         where id in (
             select id from backchannel_logout where next_attempt_at <= now()
             order by created_at limit $1 for update skip locked
         )
         returning id, client_id, session_id, subject_id, attempts",
    )
    .bind::<Int4, _>(limit)
    .load(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| Pending {
            id: row.id,
            client_id: row.client_id,
            session_id: row.session_id.into(),
            subject_id: row.subject_id.into(),
            attempts: row.attempts,
        })
        .collect())
}

/// Removes a delivered (or abandoned) logout token.
pub async fn complete(conn: &mut AsyncPgConnection, id: uuid::Uuid) -> StoreResult<()> {
    diesel::sql_query("delete from backchannel_logout where id = $1")
        .bind::<SqlUuid, _>(id)
        .execute(conn)
        .await?;
    Ok(())
}

/// Schedules another attempt at `retry_at`.
pub async fn retry(
    conn: &mut AsyncPgConnection,
    id: uuid::Uuid,
    error: &str,
    retry_at: chrono::DateTime<chrono::Utc>,
) -> StoreResult<()> {
    diesel::sql_query(
        "update backchannel_logout set attempts = attempts + 1, last_error = $2, next_attempt_at = $3
         where id = $1",
    )
    .bind::<SqlUuid, _>(id)
    .bind::<Text, _>(error)
    .bind::<Timestamptz, _>(retry_at)
    .execute(conn)
    .await?;
    Ok(())
}
