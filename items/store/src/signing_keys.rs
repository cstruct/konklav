//! Published signing keys. Only public keys are stored.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde::Serialize;

use crate::schema::signing_key;
use crate::{StoreError, StoreResult, events};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Queryable, Selectable)]
#[diesel(table_name = signing_key)]
pub struct SigningKey {
    pub kid: String,
    pub algorithm: String,
    #[serde(skip)]
    pub public_key: Vec<u8>,
    pub published_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl SigningKey {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.activated_at.is_some() && self.retired_at.is_none() && self.revoked_at.is_none()
    }
}

async fn changed(conn: &mut AsyncPgConnection, kids: &[&str]) -> QueryResult<()> {
    events::append(
        conn,
        "signing_keys.changed",
        serde_json::json!({ "kids": kids }),
    )
    .await
    .map(|_| ())
}

pub async fn list(conn: &mut AsyncPgConnection) -> StoreResult<Vec<SigningKey>> {
    Ok(signing_key::table
        .order(signing_key::published_at.asc())
        .select(SigningKey::as_select())
        .load(conn)
        .await?)
}

/// Brings published keys in line with configuration: `active` signs, every
/// key in `published` (which includes `active`) is published, and any other
/// previously active key is retired. Revoked keys stay revoked, and a
/// revoked `active` key is not reactivated. Emits `signing_keys.changed`
/// when anything changed.
// r[impl token.keys.rotation-overlap]
pub async fn sync_configured(
    conn: &mut AsyncPgConnection,
    published: &[(String, Vec<u8>)],
    active: &str,
) -> StoreResult<Vec<SigningKey>> {
    conn.transaction::<_, StoreError, _>(async |conn| {
        let mut changed_kids = Vec::new();
        for (kid, public_key) in published {
            let inserted = diesel::insert_into(signing_key::table)
                .values((
                    signing_key::kid.eq(kid),
                    signing_key::algorithm.eq("EdDSA"),
                    signing_key::public_key.eq(public_key),
                ))
                .on_conflict_do_nothing()
                .execute(conn)
                .await?;
            if inserted > 0 {
                changed_kids.push(kid.clone());
            }
        }
        let retired = diesel::update(signing_key::table)
            .filter(signing_key::kid.ne(active))
            .filter(signing_key::activated_at.is_not_null())
            .filter(signing_key::retired_at.is_null())
            .set(signing_key::retired_at.eq(diesel::dsl::now))
            .returning(signing_key::kid)
            .get_results::<String>(conn)
            .await?;
        changed_kids.extend(retired);
        let activated = diesel::update(signing_key::table.find(active))
            .filter(signing_key::activated_at.is_null())
            .filter(signing_key::revoked_at.is_null())
            .set(signing_key::activated_at.eq(diesel::dsl::now))
            .execute(conn)
            .await?;
        if activated > 0 {
            changed_kids.push(active.to_owned());
        }
        if !changed_kids.is_empty() {
            let kids = changed_kids.iter().map(String::as_str).collect::<Vec<_>>();
            changed(conn, &kids).await?;
        }
        list(conn).await
    })
    .await
}

/// Revokes a key immediately (break-glass). Returns whether it was
/// unrevoked before.
// r[impl token.keys.break-glass]
pub async fn revoke(conn: &mut AsyncPgConnection, kid: &str) -> StoreResult<bool> {
    conn.transaction::<_, StoreError, _>(async |conn| {
        let updated = diesel::update(signing_key::table.find(kid))
            .filter(signing_key::revoked_at.is_null())
            .set(signing_key::revoked_at.eq(diesel::dsl::now))
            .execute(conn)
            .await?;
        if updated == 0 {
            signing_key::table
                .find(kid)
                .select(signing_key::kid)
                .first::<String>(conn)
                .await
                .optional()?
                .ok_or(StoreError::NotFound)?;
            return Ok(false);
        }
        changed(conn, &[kid]).await?;
        Ok(true)
    })
    .await
}
