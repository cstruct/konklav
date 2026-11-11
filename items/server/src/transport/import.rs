//! Imported identity records, read into the records the import writes.

use konklav_api as api;
use konklav_store::sessions::{ClientKind, Stage};
use konklav_store::subjects::SubjectState;

use super::store_subject_kind;
use crate::import::{
    CredentialMaterial, CredentialRecord, FactorMaterial, FactorRecord, SessionRecord, SlotRecord,
    SubjectRecord,
};

pub(crate) fn subject_record(record: &api::ImportedSubject) -> SubjectRecord {
    SubjectRecord {
        id: record.id,
        kind: store_subject_kind(record.kind),
        state: match record.state {
            api::SubjectState::Active => SubjectState::Active,
            api::SubjectState::Disabled => SubjectState::Disabled,
            // Refused when written: only erasure erases a subject.
            api::SubjectState::Erased => SubjectState::Erased,
        },
        metadata: record.metadata.clone(),
    }
}

pub(crate) fn credential_record(record: api::ImportedCredential) -> CredentialRecord {
    CredentialRecord {
        id: record.id,
        subject: record.subject,
        identifier: record.identifier,
        mfa_factors_required: record.mfa_factors_required,
        session_flags: record.session_flags,
        metadata: record.metadata,
        material: match record.material {
            api::ImportedCredentialMaterial::Password { password_hash } => {
                CredentialMaterial::Password { password_hash }
            }
            api::ImportedCredentialMaterial::SecretKey { a, b } => CredentialMaterial::SecretKey {
                a: slot_record(a),
                b: slot_record(b),
            },
            api::ImportedCredentialMaterial::EmailLink => CredentialMaterial::EmailLink,
            api::ImportedCredentialMaterial::PhoneOtp => CredentialMaterial::PhoneOtp,
        },
    }
}

fn slot_record(slot: api::ImportedSecretSlot) -> SlotRecord {
    SlotRecord {
        hash: slot.hash,
        created_at: slot.created_at,
        expires_at: slot.expires_at,
    }
}

pub(crate) fn factor_record(record: api::ImportedFactor) -> FactorRecord {
    FactorRecord {
        id: record.id,
        subject: record.subject,
        active: record.active,
        material: match record.material {
            api::ImportedFactorMaterial::Totp { seed_base32 } => {
                FactorMaterial::Totp { seed_base32 }
            }
            api::ImportedFactorMaterial::EmailCode { email } => FactorMaterial::EmailCode { email },
        },
    }
}

pub(crate) fn session_record(record: api::ImportedSession) -> SessionRecord {
    SessionRecord {
        id: record.id,
        subject: record.subject,
        credential: record.credential,
        tenant: record.tenant,
        membership: record.membership,
        stage: match record.stage {
            api::SessionStage::Partial => Stage::Partial,
            api::SessionStage::Identity => Stage::Identity,
            api::SessionStage::Tenant => Stage::Tenant,
        },
        client_kind: match record.client_kind {
            api::ClientKind::Browser => ClientKind::Browser,
            api::ClientKind::Native => ClientKind::Native,
        },
        amr: record.amr,
        flags: record.flags,
        impersonator: record.impersonator,
        auth_time: record.auth_time,
        version: record.version,
        refresh_hash: record.refresh_hash,
        expires_at: record.expires_at,
        revoked_at: record.revoked_at,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::import::{CredentialRecord, FactorRecord, SessionRecord, SubjectRecord};

    /// The transport types read the same JSON as the records the
    /// `bootstrap` command writes through.
    #[test]
    fn imports_read_the_records_json() {
        let subject = json!({"id": "0195e0a0-0000-7000-8000-000000000001", "kind": "service"});
        let read: konklav_api::ImportedSubject = serde_json::from_value(subject.clone()).unwrap();
        let record: SubjectRecord = serde_json::from_value(subject).unwrap();
        assert_eq!(super::subject_record(&read), record);
        for credential in [
            json!({
                "id": "0195e0a0-0000-7000-8000-000000000002",
                "subject": "0195e0a0-0000-7000-8000-000000000001",
                "identifier": "ada@example.com",
                "kind": "password",
                "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
                "mfa_factors_required": 1,
            }),
            json!({
                "id": "0195e0a0-0000-7000-8000-000000000003",
                "subject": "0195e0a0-0000-7000-8000-000000000001",
                "identifier": "0195e0a0-0000-7000-8000-000000000003",
                "kind": "secret_key",
                "a": {"hash": "$argon2id$a", "created_at": "2026-01-01T00:00:00Z", "expires_at": null},
                "b": {"hash": "$argon2id$b", "created_at": "2026-01-01T00:00:00Z",
                      "expires_at": "2027-01-01T00:00:00Z"},
                "session_flags": ["personal_only"],
            }),
        ] {
            let read: konklav_api::ImportedCredential =
                serde_json::from_value(credential.clone()).unwrap();
            let record: CredentialRecord = serde_json::from_value(credential).unwrap();
            assert_eq!(super::credential_record(read), record);
        }
        let factor = json!({
            "id": "0195e0a0-0000-7000-8000-000000000004",
            "subject": "0195e0a0-0000-7000-8000-000000000001",
            "kind": "totp",
            "seed_base32": "JBSWY3DPEHPK3PXP",
        });
        let read: konklav_api::ImportedFactor = serde_json::from_value(factor.clone()).unwrap();
        let record: FactorRecord = serde_json::from_value(factor).unwrap();
        assert_eq!(super::factor_record(read), record);
        let session = json!({
            "id": "0195e0a0-0000-7000-8000-000000000005",
            "subject": "0195e0a0-0000-7000-8000-000000000001",
            "credential": "0195e0a0-0000-7000-8000-000000000002",
            "tenant": null,
            "membership": null,
            "stage": "identity",
            "auth_time": "2026-11-02T10:00:00Z",
            "version": 3,
            "refresh_hash": "00".repeat(32),
            "expires_at": "2026-12-02T10:00:00Z",
            "revoked_at": null,
        });
        let read: konklav_api::ImportedSession = serde_json::from_value(session.clone()).unwrap();
        let record: SessionRecord = serde_json::from_value(session).unwrap();
        assert_eq!(super::session_record(read), record);
    }
}
