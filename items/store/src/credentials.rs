//! Credentials: one table for every kind, with kind-specific data in a
//! JSON-Schema-validated `jsonb` column.

use chrono::{DateTime, Utc};
use conclave_core::{CredentialId, SubjectId};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::{Deserialize, Serialize};

use crate::schema::credential;
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    SecretKey,
}

impl CredentialKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::SecretKey => "secret_key",
        }
    }
}

/// `data` of a password credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordData {
    /// An Argon2 PHC string.
    pub hash: String,
}

/// One of the two independently rotatable slots of a secret key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretSlot {
    A,
    B,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSlotData {
    /// An Argon2 PHC string of the slot's secret.
    pub hash: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// `data` of a secret-key credential: two independently rotatable slots.
/// Both always hold a secret, so a client can switch to one while the other
/// is being rotated.
// r[impl credential.secret-key.dual]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKeyData {
    pub a: SecretSlotData,
    pub b: SecretSlotData,
}

impl SecretKeyData {
    #[must_use]
    pub fn slot(&self, slot: SecretSlot) -> &SecretSlotData {
        match slot {
            SecretSlot::A => &self.a,
            SecretSlot::B => &self.b,
        }
    }

    /// Replaces one slot, leaving the other untouched.
    pub fn set(&mut self, slot: SecretSlot, data: SecretSlotData) {
        match slot {
            SecretSlot::A => self.a = data,
            SecretSlot::B => self.b = data,
        }
    }

    /// Both slots, `a` first.
    #[must_use]
    pub fn slots(&self) -> [(SecretSlot, &SecretSlotData); 2] {
        [(SecretSlot::A, &self.a), (SecretSlot::B, &self.b)]
    }
}

/// Kind-specific credential data, stored as `kind` plus `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialData {
    Password(PasswordData),
    SecretKey(SecretKeyData),
}

impl CredentialData {
    #[must_use]
    pub fn kind(&self) -> CredentialKind {
        match self {
            Self::Password(_) => CredentialKind::Password,
            Self::SecretKey(_) => CredentialKind::SecretKey,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Password(data) => serde_json::to_value(data),
            Self::SecretKey(data) => serde_json::to_value(data),
        }
        .expect("credential data serializes")
    }

    fn from_row(kind: &str, data: serde_json::Value) -> Result<Self, diesel::result::Error> {
        let parsed = match kind {
            "password" => serde_json::from_value(data).map(Self::Password),
            "secret_key" => serde_json::from_value(data).map(Self::SecretKey),
            other => {
                return Err(diesel::result::Error::DeserializationError(
                    format!("unknown credential kind {other}").into(),
                ));
            }
        };
        parsed.map_err(|error| diesel::result::Error::DeserializationError(Box::new(error)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub id: CredentialId,
    pub subject_id: SubjectId,
    pub identifier: String,
    pub data: CredentialData,
    pub mfa_factors_required: i16,
    pub replaces: Option<CredentialId>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_reason: Option<String>,
}

impl Credential {
    #[must_use]
    pub fn kind(&self) -> CredentialKind {
        self.data.kind()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = credential)]
struct Row {
    id: uuid::Uuid,
    subject_id: uuid::Uuid,
    kind: String,
    identifier: String,
    data: serde_json::Value,
    mfa_factors_required: i16,
    replaces: Option<uuid::Uuid>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_reason: Option<String>,
}

impl TryFrom<Row> for Credential {
    type Error = diesel::result::Error;

    fn try_from(row: Row) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id.into(),
            subject_id: row.subject_id.into(),
            identifier: row.identifier,
            data: CredentialData::from_row(&row.kind, row.data)?,
            mfa_factors_required: row.mfa_factors_required,
            replaces: row.replaces.map(Into::into),
            created_at: row.created_at,
            revoked_at: row.revoked_at,
            revoked_reason: row.revoked_reason,
        })
    }
}

/// Normalizes a login identifier for storage and lookup: trimmed and
/// lowercased, so email addresses match regardless of case.
#[must_use]
pub fn normalize_identifier(identifier: &str) -> String {
    identifier.trim().to_lowercase()
}

#[derive(Debug, Clone)]
pub struct NewCredential {
    pub id: CredentialId,
    pub subject_id: SubjectId,
    /// Normalized with [`normalize_identifier`] before storing.
    pub identifier: String,
    pub data: CredentialData,
    pub mfa_factors_required: i16,
    pub replaces: Option<CredentialId>,
}

// r[impl credential.linked]
// r[impl credential.identifier.unique]
pub async fn insert(conn: &mut AsyncPgConnection, new: NewCredential) -> StoreResult<Credential> {
    let row = diesel::insert_into(credential::table)
        .values((
            credential::id.eq(new.id.as_uuid()),
            credential::subject_id.eq(new.subject_id.as_uuid()),
            credential::kind.eq(new.data.kind().as_str()),
            credential::identifier.eq(normalize_identifier(&new.identifier)),
            credential::data.eq(new.data.to_json()),
            credential::mfa_factors_required.eq(new.mfa_factors_required),
            credential::replaces.eq(new.replaces.map(uuid::Uuid::from)),
        ))
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .map_err(|error| {
            StoreError::from_unique_violation(error, "an active credential with this identifier")
        })?;
    Ok(row.try_into()?)
}

pub async fn get(conn: &mut AsyncPgConnection, id: CredentialId) -> StoreResult<Credential> {
    credential::table
        .find(id.as_uuid())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .ok_or(StoreError::NotFound)?
        .try_into()
        .map_err(StoreError::from)
}

/// Locks the credential row for the rest of the transaction.
pub async fn get_for_update(
    conn: &mut AsyncPgConnection,
    id: CredentialId,
) -> StoreResult<Credential> {
    credential::table
        .find(id.as_uuid())
        .select(Row::as_select())
        .for_update()
        .first(conn)
        .await
        .optional()?
        .ok_or(StoreError::NotFound)?
        .try_into()
        .map_err(StoreError::from)
}

/// The active credential of `kind` with this login identifier.
pub async fn find_active(
    conn: &mut AsyncPgConnection,
    kind: CredentialKind,
    identifier: &str,
) -> StoreResult<Option<Credential>> {
    credential::table
        .filter(credential::kind.eq(kind.as_str()))
        .filter(credential::identifier.eq(normalize_identifier(identifier)))
        .filter(credential::revoked_at.is_null())
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(Credential::try_from)
        .transpose()
        .map_err(StoreError::from)
}

pub async fn list_for_subject(
    conn: &mut AsyncPgConnection,
    subject: SubjectId,
) -> StoreResult<Vec<Credential>> {
    credential::table
        .filter(credential::subject_id.eq(subject.as_uuid()))
        .order(credential::created_at.asc())
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(|row| Credential::try_from(row).map_err(StoreError::from))
        .collect()
}

/// Replaces a credential's data in place. Only for changes that keep the
/// same secret, such as rehashing under new parameters or rotating one
/// slot of a secret key; replacing a password is [`insert`] plus
/// [`revoke`].
pub async fn set_data(
    conn: &mut AsyncPgConnection,
    id: CredentialId,
    data: &CredentialData,
) -> StoreResult<()> {
    let updated = diesel::update(credential::table.find(id.as_uuid()))
        .filter(credential::kind.eq(data.kind().as_str()))
        .set((
            credential::data.eq(data.to_json()),
            credential::updated_at.eq(diesel::dsl::now),
        ))
        .execute(conn)
        .await?;
    if updated == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Revokes an active credential. Revoking a revoked credential changes
/// nothing. Returns whether it was active.
// r[impl credential.history]
pub async fn revoke(
    conn: &mut AsyncPgConnection,
    id: CredentialId,
    reason: &str,
) -> StoreResult<bool> {
    let updated = diesel::update(credential::table.find(id.as_uuid()))
        .filter(credential::revoked_at.is_null())
        .set((
            credential::revoked_at.eq(diesel::dsl::now),
            credential::revoked_reason.eq(reason),
            credential::updated_at.eq(diesel::dsl::now),
        ))
        .execute(conn)
        .await?;
    if updated == 0 {
        get(conn, id).await?;
    }
    Ok(updated > 0)
}
