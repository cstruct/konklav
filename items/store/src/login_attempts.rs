//! Login attempts, for rate limiting.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::credentials::{CredentialKind, normalize_identifier};
use crate::schema::login_attempt;

pub async fn record(
    conn: &mut AsyncPgConnection,
    kind: CredentialKind,
    identifier: &str,
    succeeded: bool,
) -> QueryResult<()> {
    diesel::insert_into(login_attempt::table)
        .values((
            login_attempt::kind.eq(kind.as_str()),
            login_attempt::identifier.eq(normalize_identifier(identifier)),
            login_attempt::succeeded.eq(succeeded),
        ))
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
