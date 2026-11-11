//! Subjects.

use konklav_api as api;
use konklav_store::mfa::{Factor, FactorData};
use konklav_store::personal_data::PersonalData;
use konklav_store::subjects::{Subject, SubjectKind, SubjectState};

pub(crate) fn subject(subject: &Subject) -> api::Subject {
    api::Subject {
        id: subject.id,
        kind: subject_kind(subject.kind),
        state: match subject.state {
            SubjectState::Active => api::SubjectState::Active,
            SubjectState::Disabled => api::SubjectState::Disabled,
            SubjectState::Erased => api::SubjectState::Erased,
        },
        metadata: subject.metadata.clone(),
        metadata_etag: crate::metadata::etag(&subject.metadata),
        created_at: subject.created_at,
        erased_at: subject.erased_at,
    }
}

pub(crate) fn subject_kind(kind: SubjectKind) -> api::SubjectKind {
    match kind {
        SubjectKind::Human => api::SubjectKind::Human,
        SubjectKind::Service => api::SubjectKind::Service,
    }
}

pub(crate) fn store_subject_kind(kind: api::SubjectKind) -> SubjectKind {
    match kind {
        api::SubjectKind::Human => SubjectKind::Human,
        api::SubjectKind::Service => SubjectKind::Service,
    }
}

/// An MFA factor without its seed.
// r[impl authn.mfa.factor-listing]
pub(crate) fn mfa_factor(factor: &Factor) -> api::MfaFactor {
    let (kind, email) = match &factor.data {
        FactorData::Totp(_) => (api::MfaFactorKind::Totp, None),
        FactorData::EmailCode(data) => (api::MfaFactorKind::EmailCode, Some(data.email.clone())),
    };
    api::MfaFactor {
        id: factor.id,
        kind,
        active: factor.active,
        email,
        created_at: factor.created_at,
        removed_at: factor.removed_at,
    }
}

/// A personal data report: what the store holds, through the conversions
/// that leave secrets out.
// r[impl subject.report.no-secrets]
pub(crate) fn personal_data_report(held: PersonalData) -> api::PersonalDataReport {
    api::PersonalDataReport {
        subject: subject(&held.subject),
        credentials: held
            .credentials
            .into_iter()
            .map(super::credential)
            .collect(),
        mfa_factors: held.mfa_factors.iter().map(mfa_factor).collect(),
        memberships: held
            .memberships
            .into_iter()
            .map(super::membership)
            .collect(),
        role_assignments: held
            .role_assignments
            .into_iter()
            .map(super::role_assignment)
            .collect(),
        sessions: held.sessions.into_iter().map(super::session).collect(),
        challenges: held
            .challenges
            .into_iter()
            .map(|challenge| api::ReportedChallenge {
                id: challenge.id,
                purpose: challenge.purpose,
                recipient: challenge.recipient,
                metadata: challenge.metadata,
                created_at: challenge.created_at,
                expires_at: challenge.expires_at,
                consumed_at: challenge.consumed_at,
                revoked_at: challenge.revoked_at,
            })
            .collect(),
        login_attempts: held
            .login_attempts
            .into_iter()
            .map(|attempt| api::ReportedLoginAttempt {
                kind: attempt.kind,
                identifier: attempt.identifier,
                succeeded: attempt.succeeded,
                attempted_at: attempt.attempted_at,
                address: attempt.address,
            })
            .collect(),
    }
}
