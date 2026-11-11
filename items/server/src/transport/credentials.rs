//! Credentials, without their secret material.

use konklav_api as api;
use konklav_store::credentials::{
    Credential, CredentialData, CredentialKind, SecretSlot, SecretSlotData,
};

pub(crate) fn credential(credential: Credential) -> api::Credential {
    let (mut slots, mut passkey, mut federated) = (None, None, None);
    match &credential.data {
        CredentialData::SecretKey(data) => {
            slots = Some(api::SecretKeySlots {
                a: secret_key_slot(&data.a),
                b: secret_key_slot(&data.b),
            });
        }
        CredentialData::PublicKey(data) => {
            passkey = Some(api::Passkey {
                label: data.label.clone(),
                last_used_at: data.last_used_at,
            });
        }
        CredentialData::Federated(data) => {
            federated = Some(api::FederatedIdentity {
                provider: data.provider.clone(),
                subject: data.subject.clone(),
                email: data.email.clone(),
                email_verified: data.email_verified,
            });
        }
        CredentialData::Password(_)
        | CredentialData::EmailLink
        | CredentialData::PhoneOtp
        | CredentialData::Client => {}
    }
    api::Credential {
        id: credential.id,
        subject_id: credential.subject_id,
        kind: credential_kind(credential.kind()),
        identifier: credential.identifier,
        mfa_factors_required: credential.mfa_factors_required,
        slots,
        passkey,
        federated,
        replaces: credential.replaces,
        created_at: credential.created_at,
        revoked_at: credential.revoked_at,
        revoked_reason: credential.revoked_reason,
        break_glass: credential.break_glass,
        session_flags: credential.session_flags,
        metadata_etag: crate::metadata::etag(&credential.metadata),
        metadata: credential.metadata,
    }
}

fn secret_key_slot(slot: &SecretSlotData) -> api::SecretKeySlot {
    api::SecretKeySlot {
        created_at: slot.created_at,
        expires_at: slot.expires_at,
    }
}

fn credential_kind(kind: CredentialKind) -> api::CredentialKind {
    match kind {
        CredentialKind::Password => api::CredentialKind::Password,
        CredentialKind::SecretKey => api::CredentialKind::SecretKey,
        CredentialKind::EmailLink => api::CredentialKind::EmailLink,
        CredentialKind::PhoneOtp => api::CredentialKind::PhoneOtp,
        CredentialKind::Federated => api::CredentialKind::Federated,
        CredentialKind::Client => api::CredentialKind::Client,
        CredentialKind::PublicKey => api::CredentialKind::PublicKey,
    }
}

pub(crate) fn secret_slot(slot: SecretSlot) -> api::SecretSlot {
    match slot {
        SecretSlot::A => api::SecretSlot::A,
        SecretSlot::B => api::SecretSlot::B,
    }
}
