//! Login attempts, for rate limiting.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::credentials::{CredentialKind, normalize_identifier};
use crate::schema::login_attempt;

/// Records an attempt as failed before it is checked, so that concurrent
/// attempts all see each other; [`mark_succeeded`] corrects it once the
/// check passes. Returns its id.
pub async fn begin(
    conn: &mut AsyncPgConnection,
    kind: CredentialKind,
    identifier: &str,
    address: Option<&str>,
) -> QueryResult<i64> {
    diesel::insert_into(login_attempt::table)
        .values((
            login_attempt::kind.eq(kind.as_str()),
            login_attempt::identifier.eq(normalize_identifier(identifier)),
            login_attempt::succeeded.eq(false),
            login_attempt::address.eq(address),
        ))
        .returning(login_attempt::id)
        .get_result(conn)
        .await
}

pub async fn mark_succeeded(conn: &mut AsyncPgConnection, id: i64) -> QueryResult<()> {
    diesel::update(login_attempt::table.find(id))
        .set(login_attempt::succeeded.eq(true))
        .execute(conn)
        .await
        .map(|_| ())
}

/// Deletes an attempt that was refused before it was checked.
pub async fn forget(conn: &mut AsyncPgConnection, id: i64) -> QueryResult<()> {
    diesel::delete(login_attempt::table.find(id))
        .execute(conn)
        .await
        .map(|_| ())
}

/// Failed attempts for this identifier since `since`.
pub async fn failures_since(
    conn: &mut AsyncPgConnection,
    kind: CredentialKind,
    identifier: &str,
    since: DateTime<Utc>,
) -> QueryResult<i64> {
    login_attempt::table
        .filter(login_attempt::kind.eq(kind.as_str()))
        .filter(login_attempt::identifier.eq(normalize_identifier(identifier)))
        .filter(login_attempt::succeeded.eq(false))
        .filter(login_attempt::attempted_at.ge(since))
        .count()
        .get_result(conn)
        .await
}

/// Failed attempts of any kind from `address` since `since`.
pub async fn address_failures_since(
    conn: &mut AsyncPgConnection,
    address: &str,
    since: DateTime<Utc>,
) -> QueryResult<i64> {
    login_attempt::table
        .filter(login_attempt::address.eq(address))
        .filter(login_attempt::succeeded.eq(false))
        .filter(login_attempt::attempted_at.ge(since))
        .count()
        .get_result(conn)
        .await
}

/// The attempt kind recorded for TOTP checks, keyed by factor id.
const TOTP: &str = "mfa_totp";

/// Records a TOTP check against `factor`.
pub async fn record_totp(
    conn: &mut AsyncPgConnection,
    factor: uuid::Uuid,
    succeeded: bool,
) -> QueryResult<()> {
    diesel::insert_into(login_attempt::table)
        .values((
            login_attempt::kind.eq(TOTP),
            login_attempt::identifier.eq(factor.to_string()),
            login_attempt::succeeded.eq(succeeded),
        ))
        .execute(conn)
        .await
        .map(|_| ())
}

/// Failed TOTP checks against `factor` since `since`.
pub async fn totp_failures_since(
    conn: &mut AsyncPgConnection,
    factor: uuid::Uuid,
    since: DateTime<Utc>,
) -> QueryResult<i64> {
    login_attempt::table
        .filter(login_attempt::kind.eq(TOTP))
        .filter(login_attempt::identifier.eq(factor.to_string()))
        .filter(login_attempt::succeeded.eq(false))
        .filter(login_attempt::attempted_at.ge(since))
        .count()
        .get_result(conn)
        .await
}
