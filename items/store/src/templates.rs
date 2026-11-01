//! Templates: reusable role blueprints that cannot be assigned.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use konklav_authz::{Effect, Policy};
use serde::Serialize;

use crate::schema::{template, template_policy};
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Template {
    pub id: uuid::Uuid,
    pub key: String,
    pub description: String,
    pub metadata: serde_json::Value,
    pub policies: Vec<Policy>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub(crate) fn effect_str(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    }
}

pub(crate) fn parse_effect(value: &str) -> Effect {
    if value == "deny" {
        Effect::Deny
    } else {
        Effect::Allow
    }
}

/// The policies of the given templates, by template id.
pub(crate) async fn policies_of(
    conn: &mut AsyncPgConnection,
    ids: &[uuid::Uuid],
) -> QueryResult<Vec<(uuid::Uuid, Policy)>> {
    Ok(template_policy::table
        .filter(template_policy::template_id.eq_any(ids))
        .order((template_policy::template_id, template_policy::action))
        .select((
            template_policy::template_id,
            template_policy::action,
            template_policy::effect,
            template_policy::scope_bound,
        ))
        .load::<(uuid::Uuid, String, String, bool)>(conn)
        .await?
        .into_iter()
        .map(|(id, action, effect, scope_bound)| {
            (
                id,
                Policy {
                    action,
                    effect: parse_effect(&effect),
                    scope_bound,
                },
            )
        })
        .collect())
}

type Row = (
    uuid::Uuid,
    String,
    String,
    serde_json::Value,
    DateTime<Utc>,
    DateTime<Utc>,
);

fn columns() -> (
    template::id,
    template::key,
    template::description,
    template::metadata,
    template::created_at,
    template::updated_at,
) {
    (
        template::id,
        template::key,
        template::description,
        template::metadata,
        template::created_at,
        template::updated_at,
    )
}

async fn with_policies(conn: &mut AsyncPgConnection, rows: Vec<Row>) -> StoreResult<Vec<Template>> {
    let ids: Vec<uuid::Uuid> = rows.iter().map(|row| row.0).collect();
    let policies = policies_of(conn, &ids).await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, key, description, metadata, created_at, updated_at)| Template {
                id,
                key,
                description,
                metadata,
                policies: policies
                    .iter()
                    .filter(|(template, _)| *template == id)
                    .map(|(_, policy)| policy.clone())
                    .collect(),
                created_at,
                updated_at,
            },
        )
        .collect())
}

pub async fn get(conn: &mut AsyncPgConnection, key: &str) -> StoreResult<Template> {
    let rows = template::table
        .filter(template::key.eq(key))
        .select(columns())
        .load::<Row>(conn)
        .await?;
    with_policies(conn, rows)
        .await?
        .pop()
        .ok_or(StoreError::NotFound)
}

pub async fn list(conn: &mut AsyncPgConnection) -> StoreResult<Vec<Template>> {
    let rows = template::table
        .order(template::key.asc())
        .select(columns())
        .load::<Row>(conn)
        .await?;
    with_policies(conn, rows).await
}

/// Creates or replaces the template `key`, including all its policies.
// r[impl authz.template.blueprint]
pub async fn put(
    conn: &mut AsyncPgConnection,
    key: &str,
    description: &str,
    metadata: &serde_json::Value,
    policies: &[Policy],
) -> StoreResult<Template> {
    conn.transaction::<_, StoreError, _>(async |conn| {
        let id = diesel::insert_into(template::table)
            .values((
                template::id.eq(uuid::Uuid::now_v7()),
                template::key.eq(key),
                template::description.eq(description),
                template::metadata.eq(metadata),
            ))
            .on_conflict(template::key)
            .do_update()
            .set((
                template::description.eq(description),
                template::metadata.eq(metadata),
                template::updated_at.eq(diesel::dsl::now),
            ))
            .returning(template::id)
            .get_result::<uuid::Uuid>(conn)
            .await
            .map_err(StoreError::from_constraint)?;
        diesel::delete(template_policy::table.filter(template_policy::template_id.eq(id)))
            .execute(conn)
            .await?;
        for policy in policies {
            diesel::insert_into(template_policy::table)
                .values((
                    template_policy::template_id.eq(id),
                    template_policy::action.eq(&policy.action),
                    template_policy::effect.eq(effect_str(policy.effect)),
                    template_policy::scope_bound.eq(policy.scope_bound),
                ))
                .execute(conn)
                .await
                .map_err(StoreError::from_constraint)?;
        }
        get(conn, key).await
    })
    .await
}
