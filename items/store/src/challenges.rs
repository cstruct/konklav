//! Challenges: single-use, short-lived secrets, stored as hashes.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::{CredentialId, SessionId, SubjectId};
use serde::{Deserialize, Serialize};

use crate::schema::challenge;
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    EmailLink,
    PhoneCode,
    MfaEmailCode,
    Invite,
    ResetPassword,
    /// A federated login in progress.
    OidcLogin,
    /// Linking an identity-provider account to a signed-in subject.
    OidcLink,
    /// An authorization request at Konklav's OpenID provider, waiting for
    /// a login application to sign the subject in.
    OidcAuthorize,
    /// An authorization code issued to an OIDC client.
    OidcCode,
    /// Registering a passkey from a signed-in session.
    PasskeyRegister,
    /// Logging in, or stepping up, with a passkey.
    PasskeyLogin,
}

impl Purpose {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmailLink => "email_link",
            Self::PhoneCode => "phone_code",
            Self::MfaEmailCode => "mfa_email_code",
            Self::Invite => "invite",
            Self::ResetPassword => "reset_password",
            Self::OidcLogin => "oidc_login",
            Self::OidcLink => "oidc_link",
            Self::OidcAuthorize => "oidc_authorize",
            Self::OidcCode => "oidc_code",
            Self::PasskeyRegister => "passkey_register",
            Self::PasskeyLogin => "passkey_login",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub id: uuid::Uuid,
    pub purpose: String,
    pub subject_id: Option<SubjectId>,
    pub credential_id: Option<CredentialId>,
    pub mfa_factor_id: Option<uuid::Uuid>,
    pub session_id: Option<SessionId>,
    pub recipient: String,
    pub secret_hash: Vec<u8>,
    pub attempts: i32,
    pub max_attempts: i32,
    pub details: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

impl Challenge {
    #[must_use]
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.consumed_at.is_none() && self.expires_at > now && self.attempts < self.max_attempts
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = challenge)]
struct Row {
    id: uuid::Uuid,
    purpose: String,
    subject_id: Option<uuid::Uuid>,
    credential_id: Option<uuid::Uuid>,
    mfa_factor_id: Option<uuid::Uuid>,
    session_id: Option<uuid::Uuid>,
    recipient: String,
    secret_hash: Vec<u8>,
    attempts: i32,
    max_attempts: i32,
    details: serde_json::Value,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

impl From<Row> for Challenge {
    fn from(row: Row) -> Self {
        Self {
            id: row.id,
            purpose: row.purpose,
            subject_id: row.subject_id.map(Into::into),
            credential_id: row.credential_id.map(Into::into),
            mfa_factor_id: row.mfa_factor_id,
            session_id: row.session_id.map(Into::into),
            recipient: row.recipient,
            secret_hash: row.secret_hash,
            attempts: row.attempts,
            max_attempts: row.max_attempts,
            details: row.details,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewChallenge {
    pub id: uuid::Uuid,
    pub purpose: Purpose,
    pub subject_id: Option<SubjectId>,
    pub credential_id: Option<CredentialId>,
    pub mfa_factor_id: Option<uuid::Uuid>,
    pub session_id: Option<SessionId>,
    pub recipient: String,
    pub secret_hash: Vec<u8>,
    pub details: serde_json::Value,
    pub expires_at: DateTime<Utc>,
}

pub async fn create(conn: &mut AsyncPgConnection, new: NewChallenge) -> StoreResult<Challenge> {
    Ok(diesel::insert_into(challenge::table)
        .values((
            challenge::id.eq(new.id),
            challenge::purpose.eq(new.purpose.as_str()),
            challenge::subject_id.eq(new.subject_id.map(uuid::Uuid::from)),
            challenge::credential_id.eq(new.credential_id.map(uuid::Uuid::from)),
            challenge::mfa_factor_id.eq(new.mfa_factor_id),
            challenge::session_id.eq(new.session_id.map(uuid::Uuid::from)),
            challenge::recipient.eq(&new.recipient),
            challenge::secret_hash.eq(&new.secret_hash),
            challenge::details.eq(&new.details),
            challenge::expires_at.eq(new.expires_at),
        ))
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .map_err(StoreError::from_constraint)?
        .into())
}

pub async fn get(conn: &mut AsyncPgConnection, id: uuid::Uuid) -> StoreResult<Challenge> {
    challenge::table
        .find(id)
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Challenge::from)
        .ok_or(StoreError::NotFound)
}

/// The newest usable challenge for `purpose` sent to `recipient`, and for
/// `factor` if given.
pub async fn latest(
    conn: &mut AsyncPgConnection,
    purpose: Purpose,
    recipient: &str,
    factor: Option<uuid::Uuid>,
    now: DateTime<Utc>,
) -> StoreResult<Option<Challenge>> {
    let mut query = challenge::table
        .filter(challenge::purpose.eq(purpose.as_str()))
        .filter(challenge::recipient.eq(recipient))
        .filter(challenge::consumed_at.is_null())
        .filter(challenge::expires_at.gt(now))
        .into_boxed();
    if let Some(factor) = factor {
        query = query.filter(challenge::mfa_factor_id.eq(factor));
    }
    Ok(query
        .order(challenge::created_at.desc())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Challenge::from))
}

/// Challenges for `purpose` and `recipient` created since `since`, and for
/// `subject` if given, for rate limiting.
pub async fn count_since(
    conn: &mut AsyncPgConnection,
    purpose: Purpose,
    recipient: &str,
    subject: Option<SubjectId>,
    since: DateTime<Utc>,
) -> StoreResult<i64> {
    let mut query = challenge::table
        .filter(challenge::purpose.eq(purpose.as_str()))
        .filter(challenge::recipient.eq(recipient))
        .filter(challenge::created_at.ge(since))
        .into_boxed();
    if let Some(subject) = subject {
        query = query.filter(challenge::subject_id.eq(uuid::Uuid::from(subject)));
    }
    Ok(query.count().get_result(conn).await?)
}

/// Counts a verification attempt. Returns the challenge after counting.
// r[impl challenge.attempts]
pub async fn record_attempt(
    conn: &mut AsyncPgConnection,
    id: uuid::Uuid,
) -> StoreResult<Challenge> {
    Ok(diesel::update(challenge::table.find(id))
        .set(challenge::attempts.eq(challenge::attempts + 1))
        .returning(Row::as_returning())
        .get_result(conn)
        .await?
        .into())
}

/// Consumes a usable challenge. Returns false if it was already consumed or
/// expired, so concurrent redemptions succeed at most once.
pub async fn consume(
    conn: &mut AsyncPgConnection,
    id: uuid::Uuid,
    now: DateTime<Utc>,
) -> StoreResult<bool> {
    let consumed = diesel::update(challenge::table.find(id))
        .filter(challenge::consumed_at.is_null())
        .filter(challenge::expires_at.gt(now))
        .set(challenge::consumed_at.eq(now))
        .execute(conn)
        .await?;
    Ok(consumed > 0)
}

/// Records the session that completed a challenge (such as an accepted
/// authorization request), replacing its details. Returns false if a
/// session was already recorded.
pub async fn attach_session(
    conn: &mut AsyncPgConnection,
    id: uuid::Uuid,
    session: SessionId,
    details: &serde_json::Value,
) -> StoreResult<bool> {
    let updated = diesel::update(challenge::table.find(id))
        .filter(challenge::session_id.is_null())
        .set((
            challenge::session_id.eq(uuid::Uuid::from(session)),
            challenge::details.eq(details),
        ))
        .execute(conn)
        .await?;
    Ok(updated > 0)
}
