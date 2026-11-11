//! Credentials: one table for every kind, with kind-specific data in a
//! JSON-Schema-validated `jsonb` column.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use konklav_core::{CredentialId, SubjectId};
use serde::{Deserialize, Serialize};

use crate::schema::credential;
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    SecretKey,
    /// Log in through a magic link sent to the identifier (an email address).
    EmailLink,
    /// Log in with a code sent to the identifier (an E.164 phone number).
    PhoneOtp,
    /// Log in through an identity provider; see [`federated_identifier`].
    Federated,
    /// An OIDC client acting as a service principal (client credentials);
    /// the identifier is the client id.
    Client,
    /// A passkey; the identifier is its WebAuthn credential ID in unpadded
    /// base64url, compared exactly.
    PublicKey,
}

impl CredentialKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::SecretKey => "secret_key",
            Self::EmailLink => "email_link",
            Self::PhoneOtp => "phone_otp",
            Self::Federated => "federated",
            Self::Client => "client",
            Self::PublicKey => "public_key",
        }
    }
}

/// `data` of a federated credential: the account at the identity provider.
// r[impl federation.credential]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedData {
    /// The configured provider id.
    pub provider: String,
    /// The provider's `sub`.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// The login identifier of a federated credential. `sub` is case-sensitive
/// and identifiers are lowercased, so it is hex-encoded.
#[must_use]
pub fn federated_identifier(provider: &str, subject: &str) -> String {
    use std::fmt::Write;
    subject
        .bytes()
        .fold(format!("{provider}|"), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
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

/// `data` of a public-key credential (a passkey). Only public material is
/// stored.
// r[impl credential.public-key.stored]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyData {
    /// Chosen by the subject when registering.
    pub label: String,
    /// The attestation format the authenticator returned, such as `none`.
    pub attestation_format: String,
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
    /// The version of `state`'s encoding; see [`PUBLIC_KEY_STATE_VERSION`].
    pub state_version: u32,
    /// The verifier's view of the key (public key, algorithm, signature
    /// counter). The store does not interpret it.
    pub state: serde_json::Value,
}

/// The current encoding of [`PublicKeyData::state`].
pub const PUBLIC_KEY_STATE_VERSION: u32 = 1;

/// Kind-specific credential data, stored as `kind` plus `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialData {
    Password(PasswordData),
    SecretKey(SecretKeyData),
    EmailLink,
    PhoneOtp,
    Federated(FederatedData),
    Client,
    PublicKey(PublicKeyData),
}

impl CredentialData {
    #[must_use]
    pub fn kind(&self) -> CredentialKind {
        match self {
            Self::Password(_) => CredentialKind::Password,
            Self::SecretKey(_) => CredentialKind::SecretKey,
            Self::EmailLink => CredentialKind::EmailLink,
            Self::PhoneOtp => CredentialKind::PhoneOtp,
            Self::Federated(_) => CredentialKind::Federated,
            Self::Client => CredentialKind::Client,
            Self::PublicKey(_) => CredentialKind::PublicKey,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Password(data) => serde_json::to_value(data),
            Self::SecretKey(data) => serde_json::to_value(data),
            Self::Federated(data) => serde_json::to_value(data),
            Self::PublicKey(data) => serde_json::to_value(data),
            Self::EmailLink | Self::PhoneOtp | Self::Client => Ok(serde_json::json!({})),
        }
        .expect("credential data serializes")
    }

    fn from_row(kind: &str, data: serde_json::Value) -> Result<Self, diesel::result::Error> {
        let parsed = match kind {
            "password" => serde_json::from_value(data).map(Self::Password),
            "secret_key" => serde_json::from_value(data).map(Self::SecretKey),
            "email_link" => Ok(Self::EmailLink),
            "phone_otp" => Ok(Self::PhoneOtp),
            "federated" => serde_json::from_value(data).map(Self::Federated),
            "client" => Ok(Self::Client),
            "public_key" => serde_json::from_value(data).map(Self::PublicKey),
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
    /// A local operator credential for when every upstream is unavailable.
    pub break_glass: bool,
    /// Restrictive session flags every session started with it carries.
    pub session_flags: Vec<String>,
    pub metadata: serde_json::Value,
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
    break_glass: bool,
    session_flags: Vec<String>,
    metadata: serde_json::Value,
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
            break_glass: row.break_glass,
            session_flags: row.session_flags,
            metadata: row.metadata,
        })
    }
}

/// Normalizes a login identifier for storage and lookup: trimmed and
/// lowercased, so email addresses match regardless of case.
#[must_use]
pub fn normalize_identifier(identifier: &str) -> String {
    identifier.trim().to_lowercase()
}

/// The identifier as stored for `kind`: normalized, except for
/// credential IDs, which are case-sensitive.
fn stored_identifier(kind: CredentialKind, identifier: &str) -> String {
    match kind {
        CredentialKind::PublicKey => identifier.to_owned(),
        _ => normalize_identifier(identifier),
    }
}

#[derive(Debug, Clone)]
pub struct NewCredential {
    pub id: CredentialId,
    pub subject_id: SubjectId,
    /// Normalized with [`normalize_identifier`] before storing, except for
    /// public-key credentials.
    pub identifier: String,
    pub data: CredentialData,
    pub mfa_factors_required: i16,
    pub replaces: Option<CredentialId>,
    pub metadata: serde_json::Value,
}

// r[impl credential.linked]
// r[impl credential.identifier.unique]
pub async fn insert(conn: &mut AsyncPgConnection, new: NewCredential) -> StoreResult<Credential> {
    let row = diesel::insert_into(credential::table)
        .values((
            credential::id.eq(new.id.as_uuid()),
            credential::subject_id.eq(new.subject_id.as_uuid()),
            credential::kind.eq(new.data.kind().as_str()),
            credential::identifier.eq(stored_identifier(new.data.kind(), &new.identifier)),
            credential::data.eq(new.data.to_json()),
            credential::mfa_factors_required.eq(new.mfa_factors_required),
            credential::replaces.eq(new.replaces.map(uuid::Uuid::from)),
            credential::metadata.eq(&new.metadata),
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
        .filter(credential::identifier.eq(stored_identifier(kind, identifier)))
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

/// Inserts a credential unless one with its id exists. Returns whether it
/// was inserted. For bulk imports, which may be re-run.
pub async fn insert_if_absent(
    conn: &mut AsyncPgConnection,
    new: NewCredential,
) -> StoreResult<bool> {
    let inserted = diesel::insert_into(credential::table)
        .values((
            credential::id.eq(new.id.as_uuid()),
            credential::subject_id.eq(new.subject_id.as_uuid()),
            credential::kind.eq(new.data.kind().as_str()),
            credential::identifier.eq(stored_identifier(new.data.kind(), &new.identifier)),
            credential::data.eq(new.data.to_json()),
            credential::mfa_factors_required.eq(new.mfa_factors_required),
            credential::replaces.eq(new.replaces.map(uuid::Uuid::from)),
            credential::metadata.eq(&new.metadata),
        ))
        .on_conflict(credential::id)
        .do_nothing()
        .execute(conn)
        .await
        .map_err(StoreError::from_constraint)?;
    Ok(inserted > 0)
}

/// Sets the restrictive session flags every session started with the
/// credential carries.
// r[impl session.flags.credential]
pub async fn set_session_flags(
    conn: &mut AsyncPgConnection,
    id: CredentialId,
    flags: &[String],
) -> StoreResult<()> {
    let updated = diesel::update(credential::table.find(id.as_uuid()))
        .set(credential::session_flags.eq(flags))
        .execute(conn)
        .await?;
    if updated == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Marks a credential as a break-glass credential, or not.
// r[impl federation.break-glass]
pub async fn set_break_glass(
    conn: &mut AsyncPgConnection,
    id: CredentialId,
    break_glass: bool,
) -> StoreResult<()> {
    let updated = diesel::update(credential::table.find(id.as_uuid()))
        .set(credential::break_glass.eq(break_glass))
        .execute(conn)
        .await?;
    if updated == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Active credentials of `kind` whose identifier starts with `prefix`.
pub async fn list_active_with_prefix(
    conn: &mut AsyncPgConnection,
    kind: CredentialKind,
    prefix: &str,
) -> StoreResult<Vec<Credential>> {
    let pattern = format!(
        "{}%",
        prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    credential::table
        .filter(credential::kind.eq(kind.as_str()))
        .filter(credential::identifier.like(pattern))
        .filter(credential::revoked_at.is_null())
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(|row| row.try_into().map_err(StoreError::from))
        .collect()
}
