//! MFA factors.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::SubjectId;
use serde::{Deserialize, Serialize};

use crate::schema::mfa_factor;
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorKind {
    Totp,
    EmailCode,
}

impl FactorKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::EmailCode => "email_code",
        }
    }
}

/// A TOTP seed encrypted with a configured key, plus the last accepted step
/// (so a code can't be replayed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpData {
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_step: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailCodeData {
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactorData {
    Totp(TotpData),
    EmailCode(EmailCodeData),
}

impl FactorData {
    #[must_use]
    pub fn kind(&self) -> FactorKind {
        match self {
            Self::Totp(_) => FactorKind::Totp,
            Self::EmailCode(_) => FactorKind::EmailCode,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Totp(data) => serde_json::to_value(data),
            Self::EmailCode(data) => serde_json::to_value(data),
        }
        .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Factor {
    pub id: uuid::Uuid,
    pub subject_id: SubjectId,
    pub data: FactorData,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = mfa_factor)]
struct Row {
    id: uuid::Uuid,
    subject_id: uuid::Uuid,
    kind: String,
    data: serde_json::Value,
    active: bool,
    created_at: DateTime<Utc>,
}

impl TryFrom<Row> for Factor {
    type Error = diesel::result::Error;

    fn try_from(row: Row) -> Result<Self, Self::Error> {
        let decode =
            |e: serde_json::Error| diesel::result::Error::DeserializationError(Box::new(e));
        let data = match row.kind.as_str() {
            "totp" => FactorData::Totp(serde_json::from_value(row.data).map_err(decode)?),
            _ => FactorData::EmailCode(serde_json::from_value(row.data).map_err(decode)?),
        };
        Ok(Self {
            id: row.id,
            subject_id: row.subject_id.into(),
            data,
            active: row.active,
            created_at: row.created_at,
        })
    }
}

/// Registers an inactive factor; it becomes active once proven.
// r[impl authn.mfa.factors]
pub async fn create(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
    data: &FactorData,
) -> StoreResult<Factor> {
    let row = diesel::insert_into(mfa_factor::table)
        .values((
            mfa_factor::id.eq(uuid::Uuid::now_v7()),
            mfa_factor::subject_id.eq(subject.as_uuid()),
            mfa_factor::kind.eq(data.kind().as_str()),
            mfa_factor::data.eq(data.to_json()),
        ))
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .map_err(StoreError::from_constraint)?;
    Ok(row.try_into()?)
}

/// A factor of `subject` that hasn't been removed.
pub async fn get(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
    id: uuid::Uuid,
) -> StoreResult<Factor> {
    mfa_factor::table
        .find(id)
        .filter(mfa_factor::subject_id.eq(subject.as_uuid()))
        .filter(mfa_factor::removed_at.is_null())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .ok_or(StoreError::NotFound)?
        .try_into()
        .map_err(StoreError::from)
}

/// A factor that hasn't been removed, locked until the transaction ends.
pub async fn lock(conn: &mut AsyncPgConnection, id: uuid::Uuid) -> StoreResult<Factor> {
    mfa_factor::table
        .find(id)
        .filter(mfa_factor::removed_at.is_null())
        .select(Row::as_select())
        .for_update()
        .first(conn)
        .await
        .optional()?
        .ok_or(StoreError::NotFound)?
        .try_into()
        .map_err(StoreError::from)
}

pub async fn list(conn: &mut AsyncPgConnection, subject: SubjectId) -> StoreResult<Vec<Factor>> {
    mfa_factor::table
        .filter(mfa_factor::subject_id.eq(subject.as_uuid()))
        .filter(mfa_factor::removed_at.is_null())
        .order(mfa_factor::created_at.asc())
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(|row| Factor::try_from(row).map_err(StoreError::from))
        .collect()
}

pub async fn activate(conn: &mut AsyncPgConnection, id: uuid::Uuid) -> StoreResult<()> {
    diesel::update(mfa_factor::table.find(id))
        .set((
            mfa_factor::active.eq(true),
            mfa_factor::updated_at.eq(diesel::dsl::now),
        ))
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn set_data(
    conn: &mut AsyncPgConnection,
    id: uuid::Uuid,
    data: &FactorData,
) -> StoreResult<()> {
    diesel::update(mfa_factor::table.find(id))
        .set((
            mfa_factor::data.eq(data.to_json()),
            mfa_factor::updated_at.eq(diesel::dsl::now),
        ))
        .execute(conn)
        .await
        .map_err(StoreError::from_constraint)?;
    Ok(())
}

pub async fn remove(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
    id: uuid::Uuid,
) -> StoreResult<bool> {
    let removed = diesel::update(
        mfa_factor::table
            .find(id)
            .filter(mfa_factor::subject_id.eq(subject.as_uuid()))
            .filter(mfa_factor::removed_at.is_null()),
    )
    .set(mfa_factor::removed_at.eq(diesel::dsl::now))
    .execute(conn)
    .await?;
    Ok(removed > 0)
}

/// Imports a factor with a known id unless it exists. Returns whether it was
/// inserted.
pub async fn import(
    conn: &mut AsyncPgConnection,
    id: uuid::Uuid,
    subject: SubjectId,
    data: &FactorData,
    active: bool,
) -> StoreResult<bool> {
    let inserted = diesel::insert_into(mfa_factor::table)
        .values((
            mfa_factor::id.eq(id),
            mfa_factor::subject_id.eq(subject.as_uuid()),
            mfa_factor::kind.eq(data.kind().as_str()),
            mfa_factor::data.eq(data.to_json()),
            mfa_factor::active.eq(active),
        ))
        .on_conflict(mfa_factor::id)
        .do_nothing()
        .execute(conn)
        .await
        .map_err(StoreError::from_constraint)?;
    Ok(inserted > 0)
}
