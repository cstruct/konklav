//! Deleting what retention allows, in batches.
//!
//! Each function removes at most `batch` rows and returns how many it
//! removed, so a caller repeats it until fewer come back. The change feed's
//! own pruning is [`crate::events::prune_before`].

use chrono::{DateTime, Utc};
use diesel::sql_types::{BigInt, Timestamptz};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::StoreResult;

/// The advisory lock that keeps sweeps on one database to one at a time.
const LOCK: i64 = 0x6b6f_6e6b_7377_6570; // "konkswep"

#[derive(diesel::QueryableByName)]
struct Locked {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    locked: bool,
}

/// Takes the sweep lock for this connection's session, if no other session
/// holds it. It is released by [`unlock`] or when the connection closes.
// r[impl retention.sweep]
pub async fn try_lock(conn: &mut AsyncPgConnection) -> StoreResult<bool> {
    Ok(
        diesel::sql_query("select pg_try_advisory_lock($1) as locked")
            .bind::<BigInt, _>(LOCK)
            .get_result::<Locked>(conn)
            .await?
            .locked,
    )
}

pub async fn unlock(conn: &mut AsyncPgConnection) -> StoreResult<()> {
    diesel::sql_query("select pg_advisory_unlock($1) as locked")
        .bind::<BigInt, _>(LOCK)
        .get_result::<Locked>(conn)
        .await?;
    Ok(())
}

/// Deletes challenges that expired before `now` and were created before
/// `created_before`, the start of the longest send-limit window.
// r[impl retention.challenges]
pub async fn challenges(
    conn: &mut AsyncPgConnection,
    now: DateTime<Utc>,
    created_before: DateTime<Utc>,
    batch: i64,
) -> StoreResult<usize> {
    Ok(diesel::sql_query(
        "delete from challenge where id in (
             select id from challenge where expires_at < $1 and created_at < $2 limit $3
         )",
    )
    .bind::<Timestamptz, _>(now)
    .bind::<Timestamptz, _>(created_before)
    .bind::<BigInt, _>(batch)
    .execute(conn)
    .await?)
}

/// Deletes login attempts made before `before`, the start of the longest
/// rate-limit window.
// r[impl retention.login-attempts]
pub async fn login_attempts(
    conn: &mut AsyncPgConnection,
    before: DateTime<Utc>,
    batch: i64,
) -> StoreResult<usize> {
    Ok(diesel::sql_query(
        "delete from login_attempt where id in (
             select id from login_attempt where attempted_at < $1 limit $2
         )",
    )
    .bind::<Timestamptz, _>(before)
    .bind::<BigInt, _>(batch)
    .execute(conn)
    .await?)
}

/// Deletes recorded client-assertion `jti`s whose assertions expired.
// r[impl retention.assertions]
pub async fn client_assertions(
    conn: &mut AsyncPgConnection,
    now: DateTime<Utc>,
    batch: i64,
) -> StoreResult<usize> {
    Ok(diesel::sql_query(
        "delete from client_assertion where (client_id, jti) in (
             select client_id, jti from client_assertion where expires_at < $1 limit $2
         )",
    )
    .bind::<Timestamptz, _>(now)
    .bind::<BigInt, _>(batch)
    .execute(conn)
    .await?)
}

/// Deletes recorded bearer-assertion `jti`s whose assertions expired.
// r[impl retention.assertions]
pub async fn bearer_assertions(
    conn: &mut AsyncPgConnection,
    now: DateTime<Utc>,
    batch: i64,
) -> StoreResult<usize> {
    Ok(diesel::sql_query(
        "delete from bearer_assertion where (issuer, jti) in (
             select issuer, jti from bearer_assertion where expires_at < $1 limit $2
         )",
    )
    .bind::<Timestamptz, _>(now)
    .bind::<BigInt, _>(batch)
    .execute(conn)
    .await?)
}

/// Deletes sessions that expired or were revoked before `ended_before`,
/// with their refresh history (by cascade) and the challenges that refer
/// to them. Sessions with a pending back-channel logout, or with an
/// impersonation session started from them that is still kept, wait.
// r[impl retention.sessions]
pub async fn sessions(
    conn: &mut AsyncPgConnection,
    ended_before: DateTime<Utc>,
    batch: i64,
) -> StoreResult<usize> {
    conn.transaction(async |conn| {
        diesel::sql_query(
            "create temporary table swept_session on commit drop as
             select s.id from session s
             where (s.expires_at < $1 or s.revoked_at < $1)
               and not exists (select 1 from backchannel_logout b where b.session_id = s.id)
               and not exists (select 1 from session c where c.parent_session_id = s.id)
             limit $2
             for update of s skip locked",
        )
        .bind::<Timestamptz, _>(ended_before)
        .bind::<BigInt, _>(batch)
        .execute(conn)
        .await?;
        diesel::sql_query(
            "delete from challenge where session_id in (select id from swept_session)",
        )
        .execute(conn)
        .await?;
        Ok(
            diesel::sql_query("delete from session where id in (select id from swept_session)")
                .execute(conn)
                .await?,
        )
    })
    .await
}

/// Erases claims passed from identity providers from sessions that were
/// revoked or expired before `now`.
// r[impl retention.identity-claims]
pub async fn identity_claims(
    conn: &mut AsyncPgConnection,
    now: DateTime<Utc>,
    batch: i64,
) -> StoreResult<usize> {
    Ok(diesel::sql_query(
        "update session set identity_claims = null where id in (
             select id from session
             where identity_claims is not null
               and (revoked_at is not null or expires_at < $1)
             limit $2
         )",
    )
    .bind::<Timestamptz, _>(now)
    .bind::<BigInt, _>(batch)
    .execute(conn)
    .await?)
}

/// Erases the challenge material from stored delivery requests whose
/// challenge expired before `now`.
// r[impl retention.delivery-material]
pub async fn delivery_material(
    conn: &mut AsyncPgConnection,
    now: DateTime<Utc>,
    batch: i64,
) -> StoreResult<usize> {
    Ok(diesel::sql_query(
        "update event set payload = payload - 'material' where cursor in (
             select cursor from event
             where kind = 'delivery.requested' and payload ? 'material'
               and coalesce((payload ->> 'expires_at')::bigint, 0) < extract(epoch from $1)
             limit $2
         )",
    )
    .bind::<Timestamptz, _>(now)
    .bind::<BigInt, _>(batch)
    .execute(conn)
    .await?)
}
