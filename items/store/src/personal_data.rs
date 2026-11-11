//! What Konklav holds about one subject, for a personal data report.
//!
//! This reads the same rows that [`crate::subjects::erase`] removes. A test
//! (`items/store/tests/personal_data.rs`) holds a decision for every column
//! of the database, so the two can't drift apart unnoticed.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, Bool, Nullable, Text, Timestamptz, Uuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::SubjectId;

use crate::credentials::{self, Credential};
use crate::memberships::{self, Membership};
use crate::mfa::{self, Factor};
use crate::roles::{self, RoleAssignment};
use crate::sessions::{self, Session, SessionFilter};
use crate::subjects::{self, Subject, SubjectState};
use crate::{StoreError, StoreResult};

/// Everything held about one subject. The server decides what of it is
/// secret and leaves that out.
#[derive(Debug, Clone)]
pub struct PersonalData {
    pub subject: Subject,
    pub credentials: Vec<Credential>,
    /// Removed factors included.
    pub mfa_factors: Vec<Factor>,
    pub memberships: Vec<Membership>,
    /// Global assignments and those of the subject's memberships.
    pub role_assignments: Vec<RoleAssignment>,
    /// Newest first.
    pub sessions: Vec<Session>,
    pub challenges: Vec<Challenge>,
    pub login_attempts: Vec<LoginAttempt>,
}

/// A challenge, without its secret and its details.
#[derive(Debug, Clone, PartialEq, Eq, QueryableByName)]
pub struct Challenge {
    #[diesel(sql_type = Uuid)]
    pub id: uuid::Uuid,
    #[diesel(sql_type = Text)]
    pub purpose: String,
    #[diesel(sql_type = Text)]
    pub recipient: String,
    #[diesel(sql_type = Timestamptz)]
    pub created_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    pub expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub consumed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// One recorded attempt to log in.
#[derive(Debug, Clone, PartialEq, Eq, QueryableByName)]
pub struct LoginAttempt {
    /// The kind of credential tried.
    #[diesel(sql_type = Text)]
    pub kind: String,
    /// The login identifier tried, or an MFA factor's id.
    #[diesel(sql_type = Text)]
    pub identifier: String,
    #[diesel(sql_type = Bool)]
    pub succeeded: bool,
    #[diesel(sql_type = Timestamptz)]
    pub attempted_at: DateTime<Utc>,
    /// The client address it came from, when one was recorded.
    #[diesel(sql_type = Nullable<Text>)]
    pub address: Option<String>,
}

/// Reads what Konklav holds about `id`. For an erased subject that is the
/// subject alone.
///
/// # Errors
///
/// [`StoreError::NotFound`] for an unknown subject.
// r[impl subject.report.contents]
// r[impl subject.report.erased]
// r[impl subject.report.complete]
pub async fn of(conn: &mut AsyncPgConnection, id: SubjectId) -> StoreResult<PersonalData> {
    let subject = subjects::get(conn, id)
        .await
        .map_err(|_| StoreError::NotFound)?;
    if subject.state == SubjectState::Erased {
        // Sessions kept for retention still name the subject, but hold
        // nothing about a person any more.
        return Ok(PersonalData {
            subject,
            credentials: Vec::new(),
            mfa_factors: Vec::new(),
            memberships: Vec::new(),
            role_assignments: Vec::new(),
            sessions: Vec::new(),
            challenges: Vec::new(),
            login_attempts: Vec::new(),
        });
    }
    let memberships = memberships::list_for_subject(conn, id).await?;
    let mut role_assignments = roles::global_assignments_of(conn, id).await?;
    for membership in &memberships {
        role_assignments.extend(roles::assignments_of_membership(conn, membership.id).await?);
    }
    let filter = SessionFilter {
        subject: Some(id),
        ..Default::default()
    };
    let subject_id = uuid::Uuid::from(id);
    let recipients = subjects::recipients(conn, subject_id).await?;
    // The same rows `subjects::erase` deletes.
    let challenges = diesel::sql_query(
        "select id, purpose, recipient, created_at, expires_at, consumed_at, revoked_at
         from challenge
         where subject_id = $1
            or credential_id in (select id from credential where subject_id = $1)
            or mfa_factor_id in (select id from mfa_factor where subject_id = $1)
            or session_id in (select id from session where subject_id = $1)
            or (subject_id is null and recipient = any($2))
         order by created_at, id",
    )
    .bind::<Uuid, _>(subject_id)
    .bind::<Array<Text>, _>(&recipients)
    .get_results(conn)
    .await?;
    let login_attempts = diesel::sql_query(
        "select kind, identifier, succeeded, attempted_at, address
         from login_attempt
         where identifier = any($2)
            or identifier in (select id::text from mfa_factor where subject_id = $1)
         order by attempted_at, id",
    )
    .bind::<Uuid, _>(subject_id)
    .bind::<Array<Text>, _>(&recipients)
    .get_results(conn)
    .await?;
    Ok(PersonalData {
        credentials: credentials::list_for_subject(conn, id).await?,
        mfa_factors: mfa::list_with_removed(conn, id).await?,
        sessions: sessions::list(conn, &filter, None, None, i64::MAX).await?,
        subject,
        memberships,
        role_assignments,
        challenges,
        login_attempts,
    })
}
