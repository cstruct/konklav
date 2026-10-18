//! Subjects.

use chrono::{DateTime, Utc};
use konklav_core::SubjectId;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::schema::subject;
use crate::{StoreError, StoreResult};

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
}

impl SubjectState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    fn parse(value: &str) -> Self {
        if value == "disabled" {
            Self::Disabled
        } else {
            Self::Active
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
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = subject)]
struct Row {
    id: uuid::Uuid,
    kind: String,
    state: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<Row> for Subject {
    fn from(row: Row) -> Self {
        Self {
            id: row.id.into(),
            kind: SubjectKind::parse(&row.kind),
            state: SubjectState::parse(&row.state),
            created_at: row.created_at,
            updated_at: row.updated_at,
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
// r[impl platform.idempotency.client-ids]
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
    if existing.kind == kind {
        Ok((existing, false))
    } else {
        Err(StoreError::Conflict(format!(
            "subject {id} already exists as {}",
            existing.kind.as_str()
        )))
    }
}

/// Sets a subject's state and returns the previous one.
pub async fn set_state(
    conn: &mut AsyncPgConnection,
    id: SubjectId,
    state: SubjectState,
) -> StoreResult<SubjectState> {
    let previous = get(conn, id).await?.state;
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
