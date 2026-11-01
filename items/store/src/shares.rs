//! Shares: one tenant's scope made available to another tenant, offered
//! by the owner, effective once accepted for the recipient, and final once
//! revoked.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_authz::Scope;
use konklav_core::{ShareId, TenantId};
use serde::{Deserialize, Serialize};

use crate::schema::{share, share_action, tenant};
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareState {
    Offered,
    Accepted,
    Revoked,
}

impl ShareState {
    fn parse(value: &str) -> Self {
        match value {
            "accepted" => Self::Accepted,
            "revoked" => Self::Revoked,
            _ => Self::Offered,
        }
    }
}

/// Which side of a share: the tenant that owns the scope, or the one it is
/// shared with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Owner,
    Recipient,
}

impl Side {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Recipient => "recipient",
        }
    }
}

/// What a share offers. Changing any of it offers the share again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareTerms {
    pub owner: TenantId,
    pub scope: Scope,
    pub recipient: TenantId,
    /// The recipient's scope the share is for; tenant-wide when absent.
    #[serde(default)]
    pub recipient_scope: Option<Scope>,
    /// Actions or action groups.
    pub actions: BTreeSet<String>,
    #[serde(default)]
    pub attributes: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub valid_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Share {
    pub id: ShareId,
    #[serde(flatten)]
    pub terms: ShareTerms,
    pub state: ShareState,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Side>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = share)]
struct Row {
    id: uuid::Uuid,
    owner_tenant_id: uuid::Uuid,
    scope_kind: String,
    scope_id: String,
    recipient_tenant_id: uuid::Uuid,
    recipient_scope_kind: Option<String>,
    recipient_scope_id: Option<String>,
    attributes: serde_json::Value,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    state: String,
    accepted_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_by: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Row {
    fn into_share(self, actions: BTreeSet<String>) -> Share {
        Share {
            id: self.id.into(),
            terms: ShareTerms {
                owner: self.owner_tenant_id.into(),
                scope: Scope {
                    kind: self.scope_kind,
                    id: self.scope_id,
                },
                recipient: self.recipient_tenant_id.into(),
                recipient_scope: self
                    .recipient_scope_kind
                    .zip(self.recipient_scope_id)
                    .map(|(kind, id)| Scope { kind, id }),
                actions,
                attributes: match self.attributes {
                    serde_json::Value::Object(attributes) => attributes,
                    _ => serde_json::Map::new(),
                },
                valid_from: self.valid_from,
                valid_until: self.valid_until,
            },
            state: ShareState::parse(&self.state),
            accepted_at: self.accepted_at,
            revoked_at: self.revoked_at,
            revoked_by: self.revoked_by.map(|side| {
                if side == "recipient" {
                    Side::Recipient
                } else {
                    Side::Owner
                }
            }),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

async fn actions_of(
    conn: &mut AsyncPgConnection,
    ids: &[uuid::Uuid],
) -> StoreResult<Vec<(uuid::Uuid, String)>> {
    Ok(share_action::table
        .filter(share_action::share_id.eq_any(ids))
        .order(share_action::action.asc())
        .select((share_action::share_id, share_action::action))
        .load(conn)
        .await?)
}

async fn with_actions(conn: &mut AsyncPgConnection, rows: Vec<Row>) -> StoreResult<Vec<Share>> {
    let ids: Vec<uuid::Uuid> = rows.iter().map(|row| row.id).collect();
    let actions = actions_of(conn, &ids).await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let mine = actions
                .iter()
                .filter(|(id, _)| *id == row.id)
                .map(|(_, action)| action.clone())
                .collect();
            row.into_share(mine)
        })
        .collect())
}

pub async fn get(conn: &mut AsyncPgConnection, id: ShareId) -> StoreResult<Share> {
    let row = share::table
        .find(id.as_uuid())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .ok_or(StoreError::NotFound)?;
    with_actions(conn, vec![row])
        .await?
        .pop()
        .ok_or(StoreError::NotFound)
}

/// Shares `tenant` owns or receives, newest first; only one side when
/// `side` is given.
pub async fn list(
    conn: &mut AsyncPgConnection,
    tenant: TenantId,
    side: Option<Side>,
) -> StoreResult<Vec<Share>> {
    let tenant = tenant.as_uuid();
    let mut query = share::table.select(Row::as_select()).into_boxed();
    query = match side {
        Some(Side::Owner) => query.filter(share::owner_tenant_id.eq(tenant)),
        Some(Side::Recipient) => query.filter(share::recipient_tenant_id.eq(tenant)),
        None => query.filter(
            share::owner_tenant_id
                .eq(tenant)
                .or(share::recipient_tenant_id.eq(tenant)),
        ),
    };
    let rows = query.order(share::id.desc()).load(conn).await?;
    with_actions(conn, rows).await
}

/// Offers a share, or changes the terms of one that isn't revoked, which
/// offers it again until it is accepted anew. Offering the same terms again
/// changes nothing. A share's owner can't change.
///
/// It writes several rows: run it in a transaction.
// r[impl authz.share.shape]
// r[impl authz.share.acceptance]
// r[impl authz.share.unique]
pub async fn offer(
    conn: &mut AsyncPgConnection,
    id: ShareId,
    terms: &ShareTerms,
) -> StoreResult<Share> {
    if terms.actions.is_empty() {
        return Err(StoreError::Conflict(
            "a share needs at least one action".into(),
        ));
    }
    {
        let existing = match get(conn, id).await {
            Ok(existing) => Some(existing),
            Err(StoreError::NotFound) => None,
            Err(error) => return Err(error),
        };
        if let Some(existing) = &existing {
            if existing.state == ShareState::Revoked {
                return Err(StoreError::Conflict("the share was revoked".into()));
            }
            if existing.terms.owner != terms.owner {
                return Err(StoreError::Conflict("a share's owner can't change".into()));
            }
            if existing.terms == *terms {
                return Ok(existing.clone());
            }
        }
        let (recipient_kind, recipient_id) = terms
            .recipient_scope
            .as_ref()
            .map(|scope| (scope.kind.clone(), scope.id.clone()))
            .unzip();
        let values = (
            share::owner_tenant_id.eq(terms.owner.as_uuid()),
            share::scope_kind.eq(&terms.scope.kind),
            share::scope_id.eq(&terms.scope.id),
            share::recipient_tenant_id.eq(terms.recipient.as_uuid()),
            share::recipient_scope_kind.eq(recipient_kind),
            share::recipient_scope_id.eq(recipient_id),
            share::attributes.eq(serde_json::Value::Object(terms.attributes.clone())),
            share::valid_from.eq(terms.valid_from),
            share::valid_until.eq(terms.valid_until),
        );
        let written = if existing.is_some() {
            diesel::update(share::table.find(id.as_uuid()))
                .set((
                    values,
                    share::state.eq("offered"),
                    share::accepted_at.eq(None::<DateTime<Utc>>),
                    share::updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn)
                .await
        } else {
            diesel::insert_into(share::table)
                .values((share::id.eq(id.as_uuid()), values))
                .execute(conn)
                .await
        };
        written.map_err(|error| match error {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => StoreError::Conflict("the scope is already shared with that recipient".into()),
            other => StoreError::from_constraint(other),
        })?;
        diesel::delete(share_action::table.filter(share_action::share_id.eq(id.as_uuid())))
            .execute(conn)
            .await?;
        for action in &terms.actions {
            diesel::insert_into(share_action::table)
                .values((
                    share_action::share_id.eq(id.as_uuid()),
                    share_action::action.eq(action),
                ))
                .execute(conn)
                .await
                .map_err(StoreError::from_constraint)?;
        }
        get(conn, id).await
    }
}

/// Accepts an offered share for its recipient. Accepting it again changes
/// nothing; a revoked share can't be accepted.
// r[impl authz.share.acceptance]
pub async fn accept(conn: &mut AsyncPgConnection, id: ShareId) -> StoreResult<Share> {
    {
        let current = get(conn, id).await?;
        match current.state {
            ShareState::Accepted => Ok(current),
            ShareState::Revoked => Err(StoreError::Conflict("the share was revoked".into())),
            ShareState::Offered => {
                diesel::update(share::table.find(id.as_uuid()))
                    .set((
                        share::state.eq("accepted"),
                        share::accepted_at.eq(diesel::dsl::now),
                        share::updated_at.eq(diesel::dsl::now),
                    ))
                    .execute(conn)
                    .await?;
                get(conn, id).await
            }
        }
    }
}

/// Revokes a share for good, on behalf of `by`. Revoking it again changes
/// nothing.
pub async fn revoke(conn: &mut AsyncPgConnection, id: ShareId, by: Side) -> StoreResult<Share> {
    {
        let current = get(conn, id).await?;
        if current.state == ShareState::Revoked {
            return Ok(current);
        }
        diesel::update(share::table.find(id.as_uuid()))
            .set((
                share::state.eq("revoked"),
                share::revoked_at.eq(diesel::dsl::now),
                share::revoked_by.eq(by.as_str()),
                share::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .await?;
        get(conn, id).await
    }
}

/// The accepted shares with `recipient`, from active owner tenants, as the
/// compiler takes them.
// r[impl authz.share.ceiling]
pub async fn accepted_for(
    conn: &mut AsyncPgConnection,
    recipient: TenantId,
) -> StoreResult<Vec<konklav_authz::Share>> {
    in_state_for(conn, recipient, "accepted").await
}

/// The shares with `recipient` waiting to be accepted, from active owner
/// tenants, so explanations can say a share isn't accepted yet.
pub async fn offered_for(
    conn: &mut AsyncPgConnection,
    recipient: TenantId,
) -> StoreResult<Vec<konklav_authz::Share>> {
    in_state_for(conn, recipient, "offered").await
}

async fn in_state_for(
    conn: &mut AsyncPgConnection,
    recipient: TenantId,
    state: &str,
) -> StoreResult<Vec<konklav_authz::Share>> {
    let rows: Vec<Row> = share::table
        .inner_join(tenant::table.on(tenant::id.eq(share::owner_tenant_id)))
        .filter(share::recipient_tenant_id.eq(recipient.as_uuid()))
        .filter(share::state.eq(state))
        .filter(tenant::state.eq("active"))
        .select(Row::as_select())
        .load(conn)
        .await?;
    Ok(with_actions(conn, rows)
        .await?
        .into_iter()
        .map(|share| konklav_authz::Share {
            id: share.id,
            owner_tenant: share.terms.owner,
            scope: share.terms.scope,
            recipient_scope: share.terms.recipient_scope,
            actions: share.terms.actions,
            attributes: share.terms.attributes,
            valid_from: share.terms.valid_from.map(|at| at.timestamp()),
            valid_until: share.terms.valid_until.map(|at| at.timestamp()),
        })
        .collect())
}
