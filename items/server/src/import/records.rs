//! Identity records from a system Konklav replaces: subjects, pre-hashed
//! credentials, MFA seeds and sessions, keyed by their existing ids.

use chrono::{DateTime, Utc};
use konklav_authn::{PasswordHasher, SecretBox};
use konklav_core::{CredentialId, MembershipId, SessionId, SubjectId, TenantId};
use konklav_store::Connection;
use konklav_store::credentials::{
    self, CredentialData, NewCredential, PasswordData, SecretKeyData, SecretSlotData,
};
use konklav_store::mfa::{self, EmailCodeData, FactorData, TotpData};
use konklav_store::sessions::{
    self, ClientKind, ImportedSession, NewSession, SessionFilter, Stage,
};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::{StoreError, catalog, memberships};
use serde::Deserialize;

use super::Outcome;
use crate::error::ApiError;
use crate::subject_api;

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct SubjectRecord {
    pub(crate) id: SubjectId,
    pub(crate) kind: SubjectKind,
    #[serde(default = "active")]
    pub(crate) state: SubjectState,
    #[serde(default = "konklav_store::metadata::empty")]
    pub(crate) metadata: serde_json::Value,
}

fn active() -> SubjectState {
    SubjectState::Active
}

/// Creates a subject unless one with its id exists, then applies its state.
/// An existing subject keeps its metadata; one that is disabled loses its
/// sessions, as when the control plane disables it.
// r[impl import.idempotent]
// r[impl import.metadata]
// r[impl import.subjects.disabled]
pub(crate) async fn subject(
    conn: &mut Connection,
    record: &SubjectRecord,
) -> Result<Outcome, ApiError> {
    let created = match subjects::get(conn, record.id).await {
        Ok(existing) if existing.kind != record.kind => {
            return Err(StoreError::Conflict(format!(
                "subject {} already exists as {}",
                record.id,
                existing.kind.as_str()
            ))
            .into());
        }
        // r[impl subject.erasure.blocks-writes]
        Ok(existing) if existing.state == SubjectState::Erased => {
            return Err(StoreError::SubjectErased.into());
        }
        Ok(_) => false,
        Err(StoreError::NotFound) => {
            subjects::create_with_metadata(conn, record.id, record.kind, &record.metadata)
                .await?
                .1
        }
        Err(error) => return Err(error.into()),
    };
    if record.state != SubjectState::Active {
        subjects::set_state(conn, record.id, record.state).await?;
    }
    if record.state == SubjectState::Disabled && !created {
        let filter = SessionFilter {
            subject: Some(record.id),
            ..Default::default()
        };
        sessions::revoke(conn, &filter, None, "subject_disabled").await?;
    }
    Ok(Outcome::created_if(created))
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct SlotRecord {
    /// An Argon2 PHC string.
    pub(crate) hash: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CredentialMaterial {
    /// An Argon2 PHC string.
    Password {
        password_hash: String,
    },
    SecretKey {
        a: SlotRecord,
        b: SlotRecord,
    },
    EmailLink,
    PhoneOtp,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct CredentialRecord {
    pub(crate) id: CredentialId,
    pub(crate) subject: SubjectId,
    pub(crate) identifier: String,
    #[serde(default)]
    pub(crate) mfa_factors_required: i16,
    /// Restrictive session flags every session started with it carries.
    #[serde(default)]
    pub(crate) session_flags: Vec<String>,
    #[serde(default = "konklav_store::metadata::empty")]
    pub(crate) metadata: serde_json::Value,
    #[serde(flatten)]
    pub(crate) material: CredentialMaterial,
}

/// Refuses a hash that isn't Argon2, or that asks for more memory or time
/// than Konklav spends on a login attempt.
// r[impl import.credentials.cost-limit]
fn checked_hash(id: CredentialId, hash: String) -> Result<String, ApiError> {
    if PasswordHasher::is_argon2(&hash) {
        Ok(hash)
    } else {
        Err(ApiError::invalid_request(format!(
            "credential {id}: hashes must be Argon2 PHC strings with at most m={}, t={}, p={}",
            PasswordHasher::MAX_MEMORY_KIB,
            PasswordHasher::MAX_ITERATIONS,
            PasswordHasher::MAX_PARALLELISM
        )))
    }
}

fn slot(id: CredentialId, record: SlotRecord) -> Result<SecretSlotData, ApiError> {
    Ok(SecretSlotData {
        hash: checked_hash(id, record.hash)?,
        created_at: record.created_at,
        expires_at: record.expires_at,
    })
}

/// Stores a credential with its hashes as given (Argon2 PHC), so imported
/// passwords and secret keys keep working. An existing active secret key
/// gets the record's slots instead.
// r[impl import.credentials]
pub(crate) async fn credential(
    conn: &mut Connection,
    record: CredentialRecord,
) -> Result<Outcome, ApiError> {
    let data = match record.material {
        CredentialMaterial::Password { password_hash } => CredentialData::Password(PasswordData {
            hash: checked_hash(record.id, password_hash)?,
        }),
        CredentialMaterial::SecretKey { a, b } => CredentialData::SecretKey(SecretKeyData {
            a: slot(record.id, a)?,
            b: slot(record.id, b)?,
        }),
        CredentialMaterial::EmailLink => CredentialData::EmailLink,
        CredentialMaterial::PhoneOtp => CredentialData::PhoneOtp,
    };
    let inserted = credentials::insert_if_absent(
        conn,
        NewCredential {
            id: record.id,
            subject_id: record.subject,
            identifier: record.identifier,
            data: data.clone(),
            mfa_factors_required: record.mfa_factors_required,
            replaces: None,
            // r[impl import.metadata]
            metadata: record.metadata,
        },
    )
    .await?;
    if inserted && !record.session_flags.is_empty() {
        subject_api::check_credential_flags(conn, &record.session_flags).await?;
        credentials::set_session_flags(conn, record.id, &record.session_flags).await?;
    }
    // r[impl import.credentials.secret-key-rotation]
    if !inserted && matches!(data, CredentialData::SecretKey(_)) {
        let existing = credentials::get(conn, record.id).await?;
        if existing.subject_id == record.subject
            && existing.is_active()
            && matches!(existing.data, CredentialData::SecretKey(_))
            && existing.data != data
        {
            credentials::set_data(conn, record.id, &data).await?;
            return Ok(Outcome::Updated);
        }
    }
    Ok(Outcome::created_if(inserted))
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum FactorMaterial {
    /// The plaintext seed, base32; Konklav encrypts it on arrival.
    Totp {
        seed_base32: String,
    },
    EmailCode {
        email: String,
    },
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct FactorRecord {
    pub(crate) id: uuid::Uuid,
    pub(crate) subject: SubjectId,
    #[serde(default = "yes")]
    pub(crate) active: bool,
    #[serde(flatten)]
    pub(crate) material: FactorMaterial,
}

fn yes() -> bool {
    true
}

pub(crate) fn decode_base32(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits, mut out) = (0u32, 0, Vec::new());
    for c in input.trim_end_matches('=').bytes() {
        let value = ALPHABET.iter().position(|a| *a == c.to_ascii_uppercase())?;
        buffer = (buffer << 5) | u32::try_from(value).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// A factor ready to store: TOTP seeds are encrypted with Konklav's current
/// key, bound to the factor and its subject. Separate from [`factor`] so
/// encryption happens before a transaction opens.
// r[impl import.mfa]
// r[impl credential.mfa-seed.bound]
pub(crate) fn seal_factor(
    secrets: &SecretBox,
    id: uuid::Uuid,
    subject: SubjectId,
    material: FactorMaterial,
) -> Result<FactorData, ApiError> {
    Ok(match material {
        FactorMaterial::Totp { seed_base32 } => {
            let seed = decode_base32(&seed_base32)
                .filter(|seed| !seed.is_empty())
                .ok_or_else(|| {
                    ApiError::invalid_request(format!("factor {id}: invalid base32 seed"))
                })?;
            let sealed = secrets
                .encrypt_bound(&mfa::totp_binding(id, subject), &seed)
                .map_err(|e| ApiError::invalid_request(e.to_string()))?;
            FactorData::Totp(TotpData {
                key_id: sealed.key_id,
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
                last_step: None,
            })
        }
        FactorMaterial::EmailCode { email } => FactorData::EmailCode(EmailCodeData { email }),
    })
}

/// Stores a sealed factor unless one with its id exists.
pub(crate) async fn factor(
    conn: &mut Connection,
    id: uuid::Uuid,
    subject: SubjectId,
    data: &FactorData,
    active: bool,
) -> Result<Outcome, ApiError> {
    Ok(Outcome::created_if(
        mfa::import(conn, id, subject, data, active).await?,
    ))
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct SessionRecord {
    pub(crate) id: SessionId,
    pub(crate) subject: SubjectId,
    pub(crate) credential: CredentialId,
    pub(crate) tenant: Option<TenantId>,
    pub(crate) membership: Option<MembershipId>,
    pub(crate) stage: Stage,
    #[serde(default = "native")]
    pub(crate) client_kind: ClientKind,
    #[serde(default)]
    pub(crate) amr: Vec<String>,
    /// Session flags, which must be declared in the catalog.
    #[serde(default)]
    pub(crate) flags: Vec<String>,
    /// The subject acting as `subject`, for impersonation sessions.
    pub(crate) impersonator: Option<SubjectId>,
    pub(crate) auth_time: DateTime<Utc>,
    pub(crate) version: i64,
    /// SHA-256 (hex) of the refresh token the client will present:
    /// `<session id>.<secret>`.
    pub(crate) refresh_hash: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) revoked_at: Option<DateTime<Utc>>,
}

fn native() -> ClientKind {
    ClientKind::Native
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).ok())
        .collect()
}

/// Refuses a session whose credential, membership, tenant or flags aren't
/// ones a session of its subject could have got by signing in.
// r[impl import.sessions.consistent]
async fn check_session(conn: &mut Connection, record: &SessionRecord) -> Result<(), ApiError> {
    let invalid = |problem: &str| {
        Err(ApiError::invalid_request(format!(
            "session {}: {problem}",
            record.id
        )))
    };
    // An impersonation session keeps the impersonator's credential.
    let owners = [Some(record.subject), record.impersonator];
    match credentials::get(conn, record.credential).await {
        Ok(credential) if owners.contains(&Some(credential.subject_id)) => {}
        Ok(_) => return invalid("its credential belongs to another subject"),
        Err(StoreError::NotFound) => return invalid("its credential does not exist"),
        Err(error) => return Err(error.into()),
    }
    match (record.tenant, record.membership) {
        (None, None) if record.stage != Stage::Tenant => {}
        (Some(tenant), Some(membership)) if record.stage == Stage::Tenant => {
            let membership = match memberships::get(conn, membership).await {
                Ok(membership) => membership,
                Err(StoreError::NotFound) => return invalid("its membership does not exist"),
                Err(error) => return Err(error.into()),
            };
            if membership.subject_id != record.subject {
                return invalid("its membership belongs to another subject");
            }
            if membership.tenant_id != tenant {
                return invalid("its membership is in another tenant");
            }
        }
        _ => return invalid("a `tenant` session, and no other, needs a tenant and a membership"),
    }
    if !record.flags.is_empty() {
        let catalog = catalog::load(conn).await?;
        let declared = |flag: &String| catalog.session_flags.iter().any(|f| f.name == *flag);
        if let Some(flag) = record.flags.iter().find(|flag| !declared(flag)) {
            return invalid(&format!("session flag `{flag}` is not in the catalog"));
        }
    }
    Ok(())
}

/// Carries a live session over unless one with its id exists, so people
/// stay signed in, provided their clients can present `<session id>.<secret>`
/// refresh tokens matching the given hash.
// r[impl import.sessions]
pub(crate) async fn session(
    conn: &mut Connection,
    record: SessionRecord,
) -> Result<Outcome, ApiError> {
    let refresh_hash = decode_hex(&record.refresh_hash)
        .filter(|hash| hash.len() == 32)
        .ok_or_else(|| {
            ApiError::invalid_request(format!(
                "session {}: refresh_hash must be 64 hex characters",
                record.id
            ))
        })?;
    // A session that exists is skipped unchecked: what it named may have
    // changed since it was imported.
    match sessions::get(conn, record.id).await {
        Ok(_) => return Ok(Outcome::Skipped),
        Err(StoreError::NotFound) => {}
        Err(error) => return Err(error.into()),
    }
    check_session(conn, &record).await?;
    // A disabled subject has no sessions, so one carried over for it ends.
    // r[impl import.subjects.disabled]
    let disabled = subjects::get(conn, record.subject).await?.state == SubjectState::Disabled;
    let revoked_at = record.revoked_at.or_else(|| disabled.then(Utc::now));
    let inserted = sessions::import(
        conn,
        ImportedSession {
            session: NewSession {
                dpop_jkt: None,
                id: record.id,
                subject_id: record.subject,
                credential_id: record.credential,
                stage: record.stage,
                client_kind: record.client_kind,
                amr: record.amr,
                auth_time: record.auth_time,
                flags: record.flags,
                impersonator_subject_id: record.impersonator,
                parent_session_id: None,
                refresh_hash,
                expires_at: record.expires_at,
            },
            tenant_id: record.tenant,
            membership_id: record.membership,
            version: record.version,
            revoked_at,
        },
    )
    .await?;
    Ok(Outcome::created_if(inserted))
}
