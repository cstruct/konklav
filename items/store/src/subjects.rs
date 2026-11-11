//! Subjects.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, Text, Uuid};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use konklav_core::{Cursor, SubjectId};

use crate::schema::{oidc_client, subject};
use crate::{StoreError, StoreResult, events, sessions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Human,
    Service,
}

impl SubjectKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Service => "service",
        }
    }

    fn parse(value: &str) -> Self {
        if value == "service" {
            Self::Service
        } else {
            Self::Human
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectState {
    Active,
    Disabled,
    /// Final: what erasure leaves.
    Erased,
}

impl SubjectState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Erased => "erased",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "disabled" => Self::Disabled,
            "erased" => Self::Erased,
            _ => Self::Active,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub id: SubjectId,
    pub kind: SubjectKind,
    pub state: SubjectState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When the subject was erased, if it was.
    pub erased_at: Option<DateTime<Utc>>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = subject)]
struct Row {
    id: uuid::Uuid,
    kind: String,
    state: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    erased_at: Option<DateTime<Utc>>,
}

impl From<Row> for Subject {
    fn from(row: Row) -> Self {
        Self {
            id: row.id.into(),
            kind: SubjectKind::parse(&row.kind),
            state: SubjectState::parse(&row.state),
            created_at: row.created_at,
            updated_at: row.updated_at,
            erased_at: row.erased_at,
        }
    }
}

pub async fn get(conn: &mut AsyncPgConnection, id: SubjectId) -> StoreResult<Subject> {
    subject::table
        .find(id.as_uuid())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Subject::from)
        .ok_or(StoreError::NotFound)
}

/// Creates a subject with a caller-supplied id. Repeating the call with the
/// same kind returns the existing subject; a different kind is a conflict.
/// Returns the subject and whether it was created.
///
/// An erased subject's id is never given out again.
// r[impl platform.idempotency.client-ids]
// r[impl subject.erasure.tombstone]
pub async fn create(
    conn: &mut AsyncPgConnection,
    id: SubjectId,
    kind: SubjectKind,
) -> StoreResult<(Subject, bool)> {
    let inserted = diesel::insert_into(subject::table)
        .values((
            subject::id.eq(id.as_uuid()),
            subject::kind.eq(kind.as_str()),
        ))
        .on_conflict_do_nothing()
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .optional()?;
    if let Some(row) = inserted {
        return Ok((row.into(), true));
    }
    let existing = get(conn, id).await?;
    if existing.state == SubjectState::Erased {
        return Err(StoreError::SubjectErased);
    }
    if existing.kind == kind {
        Ok((existing, false))
    } else {
        Err(StoreError::Conflict(format!(
            "subject {id} already exists as {}",
            existing.kind.as_str()
        )))
    }
}

/// Enables or disables a subject and returns the previous state. An erased
/// subject stays erased, and only [`erase`] erases one.
// r[impl subject.state]
pub async fn set_state(
    conn: &mut AsyncPgConnection,
    id: SubjectId,
    state: SubjectState,
) -> StoreResult<SubjectState> {
    let previous = get(conn, id).await?.state;
    if previous == SubjectState::Erased {
        return Err(StoreError::SubjectErased);
    }
    if state == SubjectState::Erased {
        return Err(StoreError::Conflict(
            "a subject is erased by erasure, not by setting its state".into(),
        ));
    }
    diesel::update(subject::table.find(id.as_uuid()))
        .set((
            subject::state.eq(state.as_str()),
            subject::updated_at.eq(diesel::dsl::now),
        ))
        .execute(conn)
        .await?;
    Ok(previous)
}

/// Subjects, newest first, optionally only those of `kind` or holding an
/// active credential with this login identifier. Pass the last id of a page
/// as `before` for the next.
pub async fn list(
    conn: &mut AsyncPgConnection,
    kind: Option<SubjectKind>,
    identifier: Option<&str>,
    before: Option<SubjectId>,
    limit: i64,
) -> StoreResult<Vec<Subject>> {
    use crate::schema::credential;
    let mut query = subject::table.into_boxed();
    if let Some(kind) = kind {
        query = query.filter(subject::kind.eq(kind.as_str()));
    }
    if let Some(identifier) = identifier {
        let owners = credential::table
            .filter(credential::identifier.eq(crate::credentials::normalize_identifier(identifier)))
            .filter(credential::revoked_at.is_null())
            .select(credential::subject_id);
        query = query.filter(subject::id.eq_any(owners));
    }
    if let Some(before) = before {
        query = query.filter(subject::id.lt(uuid::Uuid::from(before)));
    }
    Ok(query
        .order(subject::id.desc())
        .limit(limit)
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(Subject::from)
        .collect())
}

/// An erased subject's id and when it was erased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasedSubject {
    pub id: SubjectId,
    pub erased_at: DateTime<Utc>,
}

/// Erased subjects in the order they were erased, ties by id, optionally
/// only those erased at or after `since`. Pass the last id of a page as
/// `after` for the next: the page then starts behind that subject, however
/// many were erased at the same instant.
///
/// [`StoreError::NotFound`] when `after` isn't an erased subject.
// r[impl subject.erasure.list]
pub async fn erased(
    conn: &mut AsyncPgConnection,
    since: Option<DateTime<Utc>>,
    after: Option<SubjectId>,
    limit: i64,
) -> StoreResult<Vec<ErasedSubject>> {
    let mut query = subject::table
        .filter(subject::erased_at.is_not_null())
        .into_boxed();
    if let Some(since) = since {
        query = query.filter(subject::erased_at.ge(since));
    }
    if let Some(after) = after {
        let after = uuid::Uuid::from(after);
        let at: Option<DateTime<Utc>> = subject::table
            .find(after)
            .select(subject::erased_at)
            .first::<Option<DateTime<Utc>>>(conn)
            .await
            .optional()?
            .flatten();
        let at = at.ok_or(StoreError::NotFound)?;
        query = query.filter(
            subject::erased_at
                .gt(at)
                .or(subject::erased_at.eq(at).and(subject::id.gt(after))),
        );
    }
    let rows: Vec<(uuid::Uuid, Option<DateTime<Utc>>)> = query
        .order((subject::erased_at.asc(), subject::id.asc()))
        .limit(limit)
        .select((subject::id, subject::erased_at))
        .load(conn)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, erased_at)| {
            Some(ErasedSubject {
                id: id.into(),
                erased_at: erased_at?,
            })
        })
        .collect())
}

/// What [`erase`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erasure {
    /// The erased subject.
    pub subject: Subject,
    /// The cursor of the `subject.erased` event, or `None` when the subject
    /// was erased before and nothing changed.
    pub cursor: Option<Cursor>,
}

/// Erases a subject: removes all personal data Konklav holds about it and
/// leaves the erased subject. Everything happens in one transaction, which
/// nests in the caller's if there is one.
///
/// What goes, in this order:
///
/// 1. its sessions are revoked and lose identity-provider claims and DPoP
///    key thumbprints
/// 2. the challenges and stored delivery requests made for it, or sent to
///    one of its recipients without naming a subject
/// 3. the login attempts for its login identifiers and MFA factors
/// 4. its MFA factors and credentials
/// 5. its role assignments; its memberships end and lose their facts, in
///    their row versions too
/// 6. the remembered batch answers that name it or one of its recipients
///
/// Erasing an erased subject changes nothing.
///
/// # Errors
///
/// [`StoreError::NotFound`] for an unknown subject, and
/// [`StoreError::Conflict`] while an OIDC client that isn't disabled
/// authenticates as it.
// r[impl subject.erasure.removes]
// r[impl subject.erasure.atomic]
pub async fn erase(conn: &mut AsyncPgConnection, id: SubjectId) -> StoreResult<Erasure> {
    conn.transaction::<_, StoreError, _>(async |conn| {
        // Writers that attach something to the subject lock its row too
        // (the foreign-key check and `subject_not_erased`), so they either
        // committed before this and are erased below, or wait and fail.
        let found: Subject = subject::table
            .find(id.as_uuid())
            .for_update()
            .select(Row::as_select())
            .first(conn)
            .await
            .optional()?
            .map(Subject::from)
            .ok_or(StoreError::NotFound)?;
        // r[impl subject.erasure.idempotent]
        if found.state == SubjectState::Erased {
            return Ok(Erasure {
                subject: found,
                cursor: None,
            });
        }
        // r[impl subject.erasure.bound-client]
        let bound = oidc_client::table
            .filter(oidc_client::service_subject_id.eq(id.as_uuid()))
            .filter(oidc_client::disabled_at.is_null())
            .select(oidc_client::id)
            .first::<String>(conn)
            .await
            .optional()?;
        if let Some(client) = bound {
            return Err(StoreError::Conflict(format!(
                "OIDC client {client} authenticates as subject {id}; disable the client first"
            )));
        }

        let subject = uuid::Uuid::from(id);
        let recipients = recipients(conn, subject).await?;
        sessions::end_for_erasure(conn, id).await?;
        for statement in [
            // Challenges and delivery requests that name no subject, such
            // as an invite to someone new, are matched by recipient. Those
            // naming another subject are that subject's.
            "delete from challenge
             where subject_id = $1
                or credential_id in (select id from credential where subject_id = $1)
                or mfa_factor_id in (select id from mfa_factor where subject_id = $1)
                or session_id in (select id from session where subject_id = $1)
                or (subject_id is null and recipient = any($2))",
            "delete from event
             where kind = 'delivery.requested'
               and (payload ->> 'subject' = $1::text
                    or (payload ->> 'subject' is null and payload ->> 'recipient' = any($2)))",
            // TOTP attempts are recorded under the factor's id.
            "delete from login_attempt
             where identifier = any($2)
                or identifier in (select id::text from mfa_factor where subject_id = $1)",
            "delete from mfa_factor where subject_id = $1",
            // Ended sessions lose their reference (`on delete set null`).
            "delete from credential where subject_id = $1",
            "delete from role_assignment
             where subject_id = $1
                or membership_id in (select id from membership where subject_id = $1)",
            "update membership set state = 'ended', facts = '{}', updated_at = now()
             where subject_id = $1 and (state = 'active' or facts <> '{}')",
            // After the update above, whose replaced version is among them.
            // r[impl subject.erasure.history]
            "update row_version set data = jsonb_set(data, '{facts}', '{}')
             where relation = 'membership'::regclass
               and key in (select jsonb_build_object('id', id) from membership where subject_id = $1)
               and data -> 'facts' <> '{}'",
            // An answer holds text as JSON does, so compare it escaped.
            "delete from batch_result
             where caller = 'subject:' || $1::text
                or strpos(answer::text, $1::text) > 0
                or exists (
                    select 1 from unnest($2) recipient
                    where strpos(answer::text, to_jsonb(recipient)::text) > 0
                )",
        ] {
            diesel::sql_query(statement)
                .bind::<Uuid, _>(subject)
                .bind::<Array<Text>, _>(&recipients)
                .execute(conn)
                .await?;
        }

        let erased: Subject = diesel::update(subject::table.find(subject))
            .set((
                subject::state.eq(SubjectState::Erased.as_str()),
                subject::erased_at.eq(diesel::dsl::now),
                subject::updated_at.eq(diesel::dsl::now),
            ))
            .returning(Row::as_returning())
            .get_result::<Row>(conn)
            .await?
            .into();
        // Last, after the session and entitlement events from above and
        // from the triggers on the rows just changed.
        // r[impl subject.erasure.event]
        // r[impl feed.subject-erased]
        let cursor = events::append(
            conn,
            "subject.erased",
            serde_json::json!({
                "subject": id,
                "erased_at": erased.erased_at.map(|at| at.timestamp()),
            }),
        )
        .await?;
        Ok(Erasure {
            subject: erased,
            cursor: Some(cursor),
        })
    })
    .await
}

/// Everything Konklav knows the subject by or reaches it at: its login
/// identifiers, the email addresses of its federated credentials and MFA
/// factors, and where its challenges were sent.
async fn recipients(conn: &mut AsyncPgConnection, subject: uuid::Uuid) -> StoreResult<Vec<String>> {
    #[derive(QueryableByName)]
    struct Known {
        #[diesel(sql_type = Text)]
        value: String,
    }
    Ok(diesel::sql_query(
        "select value from (
             select identifier as value from credential where subject_id = $1
             union select data ->> 'email' from credential where subject_id = $1
             union select data ->> 'email' from mfa_factor where subject_id = $1
             union select recipient from challenge where subject_id = $1
         ) known where value is not null",
    )
    .bind::<Uuid, _>(subject)
    .get_results::<Known>(conn)
    .await?
    .into_iter()
    .map(|known| known.value)
    .collect())
}
