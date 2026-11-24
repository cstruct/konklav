//! Access requests: a subject's request for a membership in a tenant,
//! pending until an operator approves or denies it or the subject withdraws
//! it.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::{Cursor, MembershipId, SubjectId, TenantId};
use serde::{Deserialize, Serialize};

use crate::schema::access_request;
use crate::{StoreError, StoreResult, events};

/// The change-feed event every new or decided request emits.
pub const EVENT: &str = "access_request.changed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestState {
    Pending,
    Approved,
    Denied,
    Withdrawn,
}

impl AccessRequestState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Withdrawn => "withdrawn",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "denied" => Self::Denied,
            "withdrawn" => Self::Withdrawn,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessRequest {
    pub id: uuid::Uuid,
    pub subject_id: SubjectId,
    pub tenant_id: TenantId,
    pub state: AccessRequestState,
    /// Once approved, the membership the approval created or found.
    pub membership_id: Option<MembershipId>,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    /// Who approved, denied or withdrew it; `None` for the bootstrap token
    /// or erasure.
    pub decided_by: Option<SubjectId>,
}

impl AccessRequest {
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.state == AccessRequestState::Pending
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = access_request)]
struct Row {
    id: uuid::Uuid,
    subject_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    state: String,
    membership_id: Option<uuid::Uuid>,
    created_at: DateTime<Utc>,
    decided_at: Option<DateTime<Utc>>,
    decided_by: Option<uuid::Uuid>,
}

impl From<Row> for AccessRequest {
    fn from(row: Row) -> Self {
        Self {
            id: row.id,
            subject_id: row.subject_id.into(),
            tenant_id: row.tenant_id.into(),
            // The column's check allows only these.
            state: AccessRequestState::parse(&row.state).unwrap_or(AccessRequestState::Pending),
            membership_id: row.membership_id.map(Into::into),
            created_at: row.created_at,
            decided_at: row.decided_at,
            decided_by: row.decided_by.map(Into::into),
        }
    }
}

pub async fn get(conn: &mut AsyncPgConnection, id: uuid::Uuid) -> StoreResult<AccessRequest> {
    access_request::table
        .find(id)
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Into::into)
        .ok_or(StoreError::NotFound)
}

/// The subject's pending request for the tenant, if any.
pub async fn find_pending(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
    tenant: TenantId,
) -> StoreResult<Option<AccessRequest>> {
    Ok(access_request::table
        .filter(access_request::subject_id.eq(subject.as_uuid()))
        .filter(access_request::tenant_id.eq(tenant.as_uuid()))
        .filter(access_request::state.eq("pending"))
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Into::into))
}

/// When the subject's latest denied request for the tenant was denied.
pub async fn last_denied(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
    tenant: TenantId,
) -> StoreResult<Option<DateTime<Utc>>> {
    Ok(access_request::table
        .filter(access_request::subject_id.eq(subject.as_uuid()))
        .filter(access_request::tenant_id.eq(tenant.as_uuid()))
        .filter(access_request::state.eq("denied"))
        .select(diesel::dsl::max(access_request::decided_at))
        .first::<Option<DateTime<Utc>>>(conn)
        .await?)
}

/// Creates a pending request, emitting its event. When the subject already
/// has one pending for the tenant, returns that one and `false`.
// r[impl membership.access-request]
pub async fn create(
    conn: &mut AsyncPgConnection,
    id: uuid::Uuid,
    subject: SubjectId,
    tenant: TenantId,
) -> StoreResult<(AccessRequest, bool)> {
    let inserted: Option<AccessRequest> = diesel::insert_into(access_request::table)
        .values((
            access_request::id.eq(id),
            access_request::subject_id.eq(subject.as_uuid()),
            access_request::tenant_id.eq(tenant.as_uuid()),
        ))
        .on_conflict_do_nothing()
        .returning(Row::as_returning())
        .get_result::<Row>(conn)
        .await
        .optional()
        .map_err(StoreError::from_constraint)?
        .map(Into::into);
    if let Some(request) = inserted {
        changed(conn, &request).await?;
        return Ok((request, true));
    }
    find_pending(conn, subject, tenant)
        .await?
        .map(|request| (request, false))
        .ok_or_else(|| StoreError::Conflict(format!("access request {id} already exists")))
}

/// Decides a pending request, emitting its event. `membership` is the
/// approved request's, `by` who decided. Returns `None` when the request
/// isn't pending.
// r[impl membership.access-request.decision]
// r[impl membership.access-request.decider]
pub async fn decide(
    conn: &mut AsyncPgConnection,
    id: uuid::Uuid,
    state: AccessRequestState,
    membership: Option<MembershipId>,
    by: Option<SubjectId>,
) -> StoreResult<Option<AccessRequest>> {
    let decided: Option<AccessRequest> = diesel::update(access_request::table.find(id))
        .filter(access_request::state.eq("pending"))
        .set((
            access_request::state.eq(state.as_str()),
            access_request::membership_id.eq(membership.map(uuid::Uuid::from)),
            access_request::decided_at.eq(diesel::dsl::now),
            access_request::decided_by.eq(by.map(uuid::Uuid::from)),
        ))
        .returning(Row::as_returning())
        .get_result::<Row>(conn)
        .await
        .optional()
        .map_err(StoreError::from_constraint)?
        .map(Into::into);
    if let Some(request) = &decided {
        changed(conn, request).await?;
    }
    Ok(decided)
}

/// Withdraws the subject's pending requests, as erasing it does, emitting
/// their events.
// r[impl membership.access-request.erasure]
pub async fn withdraw_all(conn: &mut AsyncPgConnection, subject: SubjectId) -> StoreResult<()> {
    let withdrawn: Vec<Row> = diesel::update(
        access_request::table
            .filter(access_request::subject_id.eq(subject.as_uuid()))
            .filter(access_request::state.eq("pending")),
    )
    .set((
        access_request::state.eq("withdrawn"),
        access_request::decided_at.eq(diesel::dsl::now),
    ))
    .returning(Row::as_returning())
    .get_results(conn)
    .await?;
    for row in withdrawn {
        changed(conn, &row.into()).await?;
    }
    Ok(())
}

/// Which requests [`list`] answers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Filter {
    pub tenant: Option<TenantId>,
    pub subject: Option<SubjectId>,
    pub state: Option<AccessRequestState>,
}

/// Requests matching `filter`, newest first, from before the request
/// `before` if given.
pub async fn list(
    conn: &mut AsyncPgConnection,
    filter: Filter,
    before: Option<uuid::Uuid>,
    limit: i64,
) -> StoreResult<Vec<AccessRequest>> {
    let mut query = access_request::table
        .select(Row::as_select())
        .order(access_request::id.desc())
        .limit(limit)
        .into_boxed();
    if let Some(tenant) = filter.tenant {
        query = query.filter(access_request::tenant_id.eq(*tenant.as_uuid()));
    }
    if let Some(subject) = filter.subject {
        query = query.filter(access_request::subject_id.eq(*subject.as_uuid()));
    }
    if let Some(state) = filter.state {
        query = query.filter(access_request::state.eq(state.as_str()));
    }
    if let Some(before) = before {
        query = query.filter(access_request::id.lt(before));
    }
    Ok(query
        .load::<Row>(conn)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

/// Appends `access_request.changed` for `request`.
// r[impl membership.access-request.event]
async fn changed(conn: &mut AsyncPgConnection, request: &AccessRequest) -> StoreResult<Cursor> {
    Ok(events::append(
        conn,
        EVENT,
        serde_json::json!({
            "access_request": request.id,
            "subject": request.subject_id,
            "tenant": request.tenant_id,
            "state": request.state,
            "membership": request.membership_id,
        }),
    )
    .await?)
}
