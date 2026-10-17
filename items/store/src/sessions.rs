//! Server-side sessions, refresh rotation with reuse detection, and
//! revocation. Every change appends a `session.changed` event in the same
//! transaction.

use chrono::{DateTime, Utc};
use conclave_core::{CredentialId, Cursor, MembershipId, SessionId, SubjectId, TenantId};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde::{Deserialize, Serialize};

use crate::schema::{session, session_previous_refresh};
use crate::{StoreError, StoreResult, events};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Partial,
    Identity,
    Tenant,
}

impl Stage {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Partial => "partial",
            Self::Identity => "identity",
            Self::Tenant => "tenant",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "partial" => Self::Partial,
            "tenant" => Self::Tenant,
            _ => Self::Identity,
        }
    }
}

/// Whether the session's refresh token travels in a cookie or in bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Browser,
    Native,
}

impl ClientKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Native => "native",
        }
    }

    fn parse(value: &str) -> Self {
        if value == "browser" {
            Self::Browser
        } else {
            Self::Native
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Session {
    pub id: SessionId,
    pub subject_id: SubjectId,
    pub credential_id: CredentialId,
    pub tenant_id: Option<TenantId>,
    pub membership_id: Option<MembershipId>,
    pub stage: Stage,
    pub client_kind: ClientKind,
    pub amr: Vec<String>,
    pub auth_time: DateTime<Utc>,
    pub flags: Vec<String>,
    pub impersonator_subject_id: Option<SubjectId>,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_reason: Option<String>,
}

impl Session {
    #[must_use]
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = session)]
struct Row {
    id: uuid::Uuid,
    subject_id: uuid::Uuid,
    credential_id: uuid::Uuid,
    tenant_id: Option<uuid::Uuid>,
    membership_id: Option<uuid::Uuid>,
    stage: String,
    client_kind: String,
    amr: Vec<Option<String>>,
    auth_time: DateTime<Utc>,
    flags: Vec<Option<String>>,
    impersonator_subject_id: Option<uuid::Uuid>,
    version: i64,
    refresh_hash: Vec<u8>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_reason: Option<String>,
}

impl From<Row> for Session {
    fn from(row: Row) -> Self {
        Self {
            id: row.id.into(),
            subject_id: row.subject_id.into(),
            credential_id: row.credential_id.into(),
            tenant_id: row.tenant_id.map(Into::into),
            membership_id: row.membership_id.map(Into::into),
            stage: Stage::parse(&row.stage),
            client_kind: ClientKind::parse(&row.client_kind),
            amr: row.amr.into_iter().flatten().collect(),
            auth_time: row.auth_time,
            flags: row.flags.into_iter().flatten().collect(),
            impersonator_subject_id: row.impersonator_subject_id.map(Into::into),
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            revoked_reason: row.revoked_reason,
        }
    }
}

fn nullable(values: &[String]) -> Vec<Option<String>> {
    values.iter().cloned().map(Some).collect()
}

/// Appends the `session.changed` event for the session's current state.
// r[impl session.revocation.event]
// r[impl feed.self-contained-session]
async fn changed(conn: &mut AsyncPgConnection, session: &Session) -> QueryResult<Cursor> {
    events::append(
        conn,
        "session.changed",
        serde_json::json!({
            "session": session.id,
            "subject": session.subject_id,
            "version": session.version,
            "revoked": session.revoked_at.is_some(),
            "expires_at": session.expires_at.timestamp(),
        }),
    )
    .await
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: SessionId,
    pub subject_id: SubjectId,
    pub credential_id: CredentialId,
    pub stage: Stage,
    pub client_kind: ClientKind,
    pub amr: Vec<String>,
    pub auth_time: DateTime<Utc>,
    pub flags: Vec<String>,
    pub impersonator_subject_id: Option<SubjectId>,
    pub refresh_hash: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

// r[impl session.server-side]
pub async fn insert(
    conn: &mut AsyncPgConnection,
    new: NewSession,
) -> StoreResult<(Session, Cursor)> {
    conn.transaction::<_, StoreError, _>(async |conn| {
        let row = diesel::insert_into(session::table)
            .values((
                session::id.eq(new.id.as_uuid()),
                session::subject_id.eq(new.subject_id.as_uuid()),
                session::credential_id.eq(new.credential_id.as_uuid()),
                session::stage.eq(new.stage.as_str()),
                session::client_kind.eq(new.client_kind.as_str()),
                session::amr.eq(nullable(&new.amr)),
                session::auth_time.eq(new.auth_time),
                session::flags.eq(nullable(&new.flags)),
                session::impersonator_subject_id
                    .eq(new.impersonator_subject_id.map(uuid::Uuid::from)),
                session::refresh_hash.eq(&new.refresh_hash),
                session::expires_at.eq(new.expires_at),
            ))
            .returning(Row::as_returning())
            .get_result(conn)
            .await?;
        let session = Session::from(row);
        let cursor = changed(conn, &session).await?;
        Ok((session, cursor))
    })
    .await
}

pub async fn get(conn: &mut AsyncPgConnection, id: SessionId) -> StoreResult<Session> {
    session::table
        .find(id.as_uuid())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Session::from)
        .ok_or(StoreError::NotFound)
}

/// The result of presenting a refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotation {
    /// The token was current: it has been replaced and the version bumped.
    Rotated(Session, Cursor),
    /// The token had already been rotated away, so the session has been
    /// revoked.
    Reused(Session, Cursor),
    /// The session is revoked or expired.
    Ended(Session),
    /// No session matches the token.
    Invalid,
}

/// Rotates a session's refresh token from `presented_hash` to `new_hash`,
/// detecting reuse of rotated-away tokens.
// r[impl session.refresh.rotation]
pub async fn rotate_refresh(
    conn: &mut AsyncPgConnection,
    id: SessionId,
    presented_hash: &[u8],
    new_hash: &[u8],
    now: DateTime<Utc>,
) -> StoreResult<Rotation> {
    conn.transaction::<_, StoreError, _>(async |conn| {
        let Some(row) = session::table
            .find(id.as_uuid())
            .select(Row::as_select())
            .for_update()
            .first(conn)
            .await
            .optional()?
        else {
            return Ok(Rotation::Invalid);
        };
        let current = row.refresh_hash.as_slice() == presented_hash;
        let session = Session::from(row);

        if !current {
            let previously_used = diesel::select(diesel::dsl::exists(
                session_previous_refresh::table
                    .filter(session_previous_refresh::session_id.eq(id.as_uuid()))
                    .filter(session_previous_refresh::refresh_hash.eq(presented_hash)),
            ))
            .get_result::<bool>(conn)
            .await?;
            if !previously_used {
                return Ok(Rotation::Invalid);
            }
            if session.revoked_at.is_some() {
                return Ok(Rotation::Ended(session));
            }
            let revoked = revoke_ids(conn, &[id], "refresh_token_reused").await?;
            let (session, cursor) = revoked.into_iter().next().ok_or(StoreError::NotFound)?;
            return Ok(Rotation::Reused(session, cursor));
        }
        if !session.is_active_at(now) {
            return Ok(Rotation::Ended(session));
        }

        diesel::insert_into(session_previous_refresh::table)
            .values((
                session_previous_refresh::session_id.eq(id.as_uuid()),
                session_previous_refresh::refresh_hash.eq(presented_hash),
            ))
            .on_conflict_do_nothing()
            .execute(conn)
            .await?;
        let row = diesel::update(session::table.find(id.as_uuid()))
            .set((
                session::refresh_hash.eq(new_hash),
                session::version.eq(session::version + 1),
                session::updated_at.eq(diesel::dsl::now),
            ))
            .returning(Row::as_returning())
            .get_result(conn)
            .await?;
        let session = Session::from(row);
        let cursor = changed(conn, &session).await?;
        Ok(Rotation::Rotated(session, cursor))
    })
    .await
}

/// Which sessions to act on. Every set field must match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SessionFilter {
    pub session: Option<SessionId>,
    pub subject: Option<SubjectId>,
    pub credential: Option<CredentialId>,
    pub tenant: Option<TenantId>,
    pub membership: Option<MembershipId>,
}

impl SessionFilter {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn apply<'a>(
        &self,
        mut query: session::BoxedQuery<'a, diesel::pg::Pg>,
    ) -> session::BoxedQuery<'a, diesel::pg::Pg> {
        if let Some(id) = self.session {
            query = query.filter(session::id.eq(uuid::Uuid::from(id)));
        }
        if let Some(id) = self.subject {
            query = query.filter(session::subject_id.eq(uuid::Uuid::from(id)));
        }
        if let Some(id) = self.credential {
            query = query.filter(session::credential_id.eq(uuid::Uuid::from(id)));
        }
        if let Some(id) = self.tenant {
            query = query.filter(session::tenant_id.eq(uuid::Uuid::from(id)));
        }
        if let Some(id) = self.membership {
            query = query.filter(session::membership_id.eq(uuid::Uuid::from(id)));
        }
        query
    }
}

async fn revoke_ids(
    conn: &mut AsyncPgConnection,
    ids: &[SessionId],
    reason: &str,
) -> StoreResult<Vec<(Session, Cursor)>> {
    let ids = ids
        .iter()
        .map(|id| uuid::Uuid::from(*id))
        .collect::<Vec<_>>();
    let rows = diesel::update(session::table.filter(session::id.eq_any(&ids)))
        .filter(session::revoked_at.is_null())
        .set((
            session::revoked_at.eq(diesel::dsl::now),
            session::revoked_reason.eq(reason),
            session::version.eq(session::version + 1),
            session::updated_at.eq(diesel::dsl::now),
        ))
        .returning(Row::as_returning())
        .get_results(conn)
        .await?;
    let mut revoked = Vec::with_capacity(rows.len());
    for row in rows {
        let session = Session::from(row);
        let cursor = changed(conn, &session).await?;
        revoked.push((session, cursor));
    }
    Ok(revoked)
}

/// Revokes every unrevoked session matching `filter`, except `keep`.
/// Returns the revoked sessions with their events' cursors.
///
/// An empty filter matches nothing rather than everything.
// r[impl session.revocation.targets]
pub async fn revoke(
    conn: &mut AsyncPgConnection,
    filter: &SessionFilter,
    keep: Option<SessionId>,
    reason: &str,
) -> StoreResult<Vec<(Session, Cursor)>> {
    if filter.is_empty() {
        return Ok(Vec::new());
    }
    // The UPDATE re-checks `revoked_at`, so a session revoked concurrently
    // between the SELECT and the UPDATE is skipped rather than revoked twice.
    conn.transaction::<_, StoreError, _>(async |conn| {
        let mut query = filter
            .apply(session::table.into_boxed())
            .filter(session::revoked_at.is_null())
            .select(session::id);
        if let Some(keep) = keep {
            query = query.filter(session::id.ne(uuid::Uuid::from(keep)));
        }
        let ids = query
            .load::<uuid::Uuid>(conn)
            .await?
            .into_iter()
            .map(SessionId::from)
            .collect::<Vec<_>>();
        revoke_ids(conn, &ids, reason).await
    })
    .await
}

/// Lists sessions matching `filter`, newest first, `limit` at a time.
/// Pass the last id of a page as `before` to get the next one.
// r[impl session.history]
pub async fn list(
    conn: &mut AsyncPgConnection,
    filter: &SessionFilter,
    active_at: Option<DateTime<Utc>>,
    before: Option<SessionId>,
    limit: i64,
) -> StoreResult<Vec<Session>> {
    let mut query = filter.apply(session::table.into_boxed());
    if let Some(now) = active_at {
        query = query
            .filter(session::revoked_at.is_null())
            .filter(session::expires_at.gt(now));
    }
    if let Some(before) = before {
        query = query.filter(session::id.lt(uuid::Uuid::from(before)));
    }
    Ok(query
        .order(session::id.desc())
        .limit(limit)
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(Session::from)
        .collect())
}

/// Whether `hash` is the session's current refresh token hash.
pub async fn refresh_matches(
    conn: &mut AsyncPgConnection,
    id: SessionId,
    hash: &[u8],
) -> StoreResult<bool> {
    Ok(diesel::select(diesel::dsl::exists(
        session::table
            .filter(session::id.eq(id.as_uuid()))
            .filter(session::refresh_hash.eq(hash)),
    ))
    .get_result(conn)
    .await?)
}

/// Points a session at a tenant through one of the subject's memberships,
/// bumping its version so tokens for the previous context stop working.
// r[impl authn.login.single-tenant-context]
pub async fn select_tenant(
    conn: &mut AsyncPgConnection,
    id: SessionId,
    tenant: TenantId,
    membership: MembershipId,
) -> StoreResult<(Session, Cursor)> {
    conn.transaction::<_, StoreError, _>(async |conn| {
        let row = diesel::update(session::table.find(id.as_uuid()))
            .filter(session::revoked_at.is_null())
            .set((
                session::stage.eq(Stage::Tenant.as_str()),
                session::tenant_id.eq(tenant.as_uuid()),
                session::membership_id.eq(membership.as_uuid()),
                session::version.eq(session::version + 1),
                session::updated_at.eq(diesel::dsl::now),
            ))
            .returning(Row::as_returning())
            .get_result(conn)
            .await
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let session = Session::from(row);
        let cursor = changed(conn, &session).await?;
        Ok((session, cursor))
    })
    .await
}
