//! Bulk import of identity data from a system Konklav replaces, keyed by
//! the records' existing ids so imports can be re-run.

use chrono::{DateTime, Utc};
use konklav_core::{CredentialId, MembershipId, SessionId, SubjectId, TenantId};
use serde::{Deserialize, Serialize};

use crate::{ClientKind, SessionStage, SubjectKind, SubjectState};

/// What an import did, record by record.
// The field names are the API's.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Imported {
    /// Records created.
    pub imported: usize,
    /// Records that existed already and were left alone.
    pub skipped: usize,
    /// Existing secret keys whose slots were replaced.
    pub updated: usize,
}

/// A subject; an existing one keeps its kind but takes the record's state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportedSubject {
    pub id: SubjectId,
    pub kind: SubjectKind,
    #[serde(default = "active")]
    pub state: SubjectState,
}

fn active() -> SubjectState {
    SubjectState::Active
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportSubjects {
    pub subjects: Vec<ImportedSubject>,
}

/// One slot of an imported secret key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportedSecretSlot {
    /// The slot secret's hash, an Argon2 PHC string.
    pub hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// A credential's kind and its hashed material, stored as given.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportedCredentialMaterial {
    #[schema(title = "ImportedCredentialMaterialPassword")]
    Password {
        /// The password's hash, an Argon2 PHC string; never the password.
        password_hash: String,
    },
    /// Replaces the slots of an existing active secret key with the same
    /// id and subject.
    #[schema(title = "ImportedCredentialMaterialSecretKey")]
    SecretKey {
        a: ImportedSecretSlot,
        b: ImportedSecretSlot,
    },
    #[schema(title = "ImportedCredentialMaterialEmailLink")]
    EmailLink,
    #[schema(title = "ImportedCredentialMaterialPhoneOtp")]
    PhoneOtp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportedCredential {
    pub id: CredentialId,
    pub subject: SubjectId,
    pub identifier: String,
    #[serde(default)]
    pub mfa_factors_required: i16,
    /// Restrictive session flags every session started with it carries.
    #[serde(default)]
    pub session_flags: Vec<String>,
    #[serde(flatten)]
    pub material: ImportedCredentialMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportCredentials {
    pub credentials: Vec<ImportedCredential>,
}

/// An MFA factor's kind and material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportedFactorMaterial {
    #[schema(title = "ImportedFactorMaterialTotp")]
    Totp {
        /// The plaintext seed, base32; Konklav encrypts it on arrival.
        seed_base32: String,
    },
    #[schema(title = "ImportedFactorMaterialEmailCode")]
    EmailCode { email: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportedFactor {
    pub id: uuid::Uuid,
    pub subject: SubjectId,
    #[serde(default = "yes")]
    pub active: bool,
    #[serde(flatten)]
    pub material: ImportedFactorMaterial,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportFactors {
    pub factors: Vec<ImportedFactor>,
}

/// A live session, carried over so people stay signed in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportedSession {
    pub id: SessionId,
    pub subject: SubjectId,
    pub credential: CredentialId,
    pub tenant: Option<TenantId>,
    pub membership: Option<MembershipId>,
    pub stage: SessionStage,
    #[serde(default = "native")]
    pub client_kind: ClientKind,
    #[serde(default)]
    pub amr: Vec<String>,
    /// Session flags, which must be declared in the catalog.
    #[serde(default)]
    pub flags: Vec<String>,
    /// The subject acting as `subject`, for impersonation sessions.
    pub impersonator: Option<SubjectId>,
    pub auth_time: DateTime<Utc>,
    pub version: i64,
    /// SHA-256 (hex) of the refresh token the client will present:
    /// `<session id>.<secret>`.
    pub refresh_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

fn native() -> ClientKind {
    ClientKind::Native
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportSessions {
    pub sessions: Vec<ImportedSession>,
}
