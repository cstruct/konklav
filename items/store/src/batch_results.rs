//! The answers of committed batches that carried an idempotency key, kept
//! per caller until the key's lifetime has passed.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;
use crate::schema::batch_result;

/// A remembered answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remembered {
    /// Identifies the batch's operations, so another batch reusing the key
    /// can be told apart.
    pub request_hash: Vec<u8>,
    pub answer: serde_json::Value,
}

/// The answer remembered for `caller`'s `key`, unless it has expired.
pub async fn get(
    conn: &mut AsyncPgConnection,
    caller: &str,
    key: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<Remembered>> {
    Ok(batch_result::table
        .find((caller, key))
        .filter(batch_result::expires_at.gt(now))
        .select((batch_result::request_hash, batch_result::answer))
        .first::<(Vec<u8>, serde_json::Value)>(conn)
        .await
        .optional()?
        .map(|(request_hash, answer)| Remembered {
            request_hash,
            answer,
        }))
}

/// Remembers an answer until `expires_at`, replacing an expired one for the
/// same key. Returns `false`, remembering nothing, when an unexpired answer
/// is already there, such as one a concurrent batch with the key committed.
// r[impl platform.batch.idempotency-key]
pub async fn remember(
    conn: &mut AsyncPgConnection,
    caller: &str,
    key: &str,
    remembered: &Remembered,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> StoreResult<bool> {
    use diesel::sql_types::{Bytea, Jsonb, Text, Timestamptz};
    let written = diesel::sql_query(
        "insert into batch_result (caller, key, request_hash, answer, created_at, expires_at)
         values ($1, $2, $3, $4, $5, $6)
         on conflict (caller, key) do update set
             request_hash = excluded.request_hash, answer = excluded.answer,
             created_at = excluded.created_at, expires_at = excluded.expires_at
         where batch_result.expires_at <= $5",
    )
    .bind::<Text, _>(caller)
    .bind::<Text, _>(key)
    .bind::<Bytea, _>(&remembered.request_hash)
    .bind::<Jsonb, _>(&remembered.answer)
    .bind::<Timestamptz, _>(now)
    .bind::<Timestamptz, _>(expires_at)
    .execute(conn)
    .await?;
    Ok(written > 0)
}
