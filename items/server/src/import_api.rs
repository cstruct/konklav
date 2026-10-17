//! Bulk import of identity data from a system Conclave replaces: subjects,
//! pre-hashed credentials, MFA seeds and sessions, keyed by their existing
//! ids so imports can be re-run.
//!
//! Tenants, memberships, the catalog, templates, roles and assignments are
//! imported through the ordinary (idempotent) control-plane endpoints.

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use conclave_core::{CredentialId, MembershipId, SessionId, SubjectId, TenantId};
use conclave_store::credentials::{
    self, CredentialData, NewCredential, PasswordData, SecretKeyData, SecretSlotData,
};
use conclave_store::mfa::{self, EmailCodeData, FactorData, TotpData};
use conclave_store::sessions::{self, ClientKind, ImportedSession, NewSession, Stage};
use conclave_store::subjects::{self, SubjectKind, SubjectState};
use diesel_async::AsyncConnection;
use serde::{Deserialize, Serialize};

use crate::control_api::guard;
use crate::error::{ApiError, ApiJson};
use crate::{AppState, capabilities};

pub fn routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/import/subjects", post(import_subjects))
        .route("/import/credentials", post(import_credentials))
        .route("/import/mfa-factors", post(import_factors))
        .route("/import/sessions", post(import_sessions))
        .route_layer(guard(state, capabilities::IMPORT))
}

#[derive(Serialize, Default)]
struct Imported {
    imported: usize,
    skipped: usize,
}

impl Imported {
    fn count(&mut self, inserted: bool) {
        if inserted {
            self.imported += 1;
        } else {
            self.skipped += 1;
        }
    }
}

#[derive(Deserialize)]
struct SubjectRecord {
    id: SubjectId,
    kind: SubjectKind,
    #[serde(default = "active")]
    state: SubjectState,
}

fn active() -> SubjectState {
    SubjectState::Active
}

#[derive(Deserialize)]
struct Subjects {
    subjects: Vec<SubjectRecord>,
}

/// `POST /v1/import/subjects`
// r[impl import.idempotent]
async fn import_subjects(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Subjects>,
) -> Result<Json<Imported>, ApiError> {
    let mut conn = state.pool.get().await?;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in &body.subjects {
                let (_, created) = subjects::create(conn, record.id, record.kind).await?;
                if record.state != SubjectState::Active {
                    subjects::set_state(conn, record.id, record.state).await?;
                }
                result.count(created);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
struct SlotRecord {
    /// An Argon2 PHC string.
    hash: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CredentialMaterial {
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

#[derive(Deserialize)]
struct CredentialRecord {
    id: CredentialId,
    subject: SubjectId,
    identifier: String,
    #[serde(default)]
    mfa_factors_required: i16,
    #[serde(flatten)]
    material: CredentialMaterial,
}

#[derive(Deserialize)]
struct Credentials {
    credentials: Vec<CredentialRecord>,
}

fn slot(record: SlotRecord) -> SecretSlotData {
    SecretSlotData {
        hash: record.hash,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

/// `POST /v1/import/credentials`: hashes are stored as given (Argon2 PHC),
/// so imported passwords and secret keys keep working.
// r[impl import.credentials]
async fn import_credentials(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Credentials>,
) -> Result<Json<Imported>, ApiError> {
    let mut conn = state.pool.get().await?;
    let records = body.credentials;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in records {
                let data = match record.material {
                    CredentialMaterial::Password { password_hash } => {
                        CredentialData::Password(PasswordData {
                            hash: password_hash,
                        })
                    }
                    CredentialMaterial::SecretKey { a, b } => {
                        CredentialData::SecretKey(SecretKeyData {
                            a: slot(a),
                            b: slot(b),
                        })
                    }
                    CredentialMaterial::EmailLink => CredentialData::EmailLink,
                    CredentialMaterial::PhoneOtp => CredentialData::PhoneOtp,
                };
                let inserted = credentials::insert_if_absent(
                    conn,
                    NewCredential {
                        id: record.id,
                        subject_id: record.subject,
                        identifier: record.identifier,
                        data,
                        mfa_factors_required: record.mfa_factors_required,
                        replaces: None,
                    },
                )
                .await?;
                result.count(inserted);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FactorMaterial {
    /// The plaintext seed, base32; Conclave encrypts it on arrival.
    Totp {
        seed_base32: String,
    },
    EmailCode {
        email: String,
    },
}

#[derive(Deserialize)]
struct FactorRecord {
    id: uuid::Uuid,
    subject: SubjectId,
    #[serde(default = "yes")]
    active: bool,
    #[serde(flatten)]
    material: FactorMaterial,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct Factors {
    factors: Vec<FactorRecord>,
}

fn decode_base32(input: &str) -> Option<Vec<u8>> {
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

/// `POST /v1/import/mfa-factors`: TOTP seeds arrive in plaintext over the
/// control plane and are encrypted with Conclave's current key.
// r[impl import.mfa]
async fn import_factors(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Factors>,
) -> Result<Json<Imported>, ApiError> {
    let mut prepared = Vec::with_capacity(body.factors.len());
    for record in body.factors {
        let data = match record.material {
            FactorMaterial::Totp { seed_base32 } => {
                let seed = decode_base32(&seed_base32)
                    .filter(|seed| !seed.is_empty())
                    .ok_or_else(|| {
                        ApiError::invalid_request(format!(
                            "factor {}: invalid base32 seed",
                            record.id
                        ))
                    })?;
                let sealed = state
                    .auth
                    .secrets
                    .encrypt(&seed)
                    .map_err(|e| ApiError::invalid_request(e.to_string()))?;
                FactorData::Totp(TotpData {
                    key_id: sealed.key_id,
                    nonce: sealed.nonce,
                    ciphertext: sealed.ciphertext,
                    last_step: None,
                })
            }
            FactorMaterial::EmailCode { email } => FactorData::EmailCode(EmailCodeData { email }),
        };
        prepared.push((record.id, record.subject, data, record.active));
    }
    let mut conn = state.pool.get().await?;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for (id, subject, data, active) in &prepared {
                result.count(mfa::import(conn, *id, *subject, data, *active).await?);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
struct SessionRecord {
    id: SessionId,
    subject: SubjectId,
    credential: CredentialId,
    tenant: Option<TenantId>,
    membership: Option<MembershipId>,
    stage: Stage,
    #[serde(default = "native")]
    client_kind: ClientKind,
    #[serde(default)]
    amr: Vec<String>,
    auth_time: DateTime<Utc>,
    version: i64,
    /// SHA-256 (hex) of the refresh token the client will present:
    /// `<session id>.<secret>`.
    refresh_hash: String,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

fn native() -> ClientKind {
    ClientKind::Native
}

#[derive(Deserialize)]
struct Sessions {
    sessions: Vec<SessionRecord>,
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

/// `POST /v1/import/sessions`: carries live sessions over so people stay
/// signed in, provided their clients can present `<session id>.<secret>`
/// refresh tokens matching the given hash.
// r[impl import.sessions]
async fn import_sessions(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Sessions>,
) -> Result<Json<Imported>, ApiError> {
    let mut conn = state.pool.get().await?;
    let records = body.sessions;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in records {
                let refresh_hash = decode_hex(&record.refresh_hash)
                    .filter(|hash| hash.len() == 32)
                    .ok_or_else(|| {
                        ApiError::invalid_request(format!(
                            "session {}: refresh_hash must be 64 hex characters",
                            record.id
                        ))
                    })?;
                let inserted = sessions::import(
                    conn,
                    ImportedSession {
                        session: NewSession {
                            id: record.id,
                            subject_id: record.subject,
                            credential_id: record.credential,
                            stage: record.stage,
                            client_kind: record.client_kind,
                            amr: record.amr,
                            auth_time: record.auth_time,
                            flags: Vec::new(),
                            impersonator_subject_id: None,
                            parent_session_id: None,
                            refresh_hash,
                            expires_at: record.expires_at,
                        },
                        tenant_id: record.tenant,
                        membership_id: record.membership,
                        version: record.version,
                        revoked_at: record.revoked_at,
                    },
                )
                .await?;
                result.count(inserted);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}
