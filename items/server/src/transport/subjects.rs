//! Subjects.

use konklav_api as api;
use konklav_store::subjects::{Subject, SubjectKind, SubjectState};

pub(crate) fn subject(subject: &Subject) -> api::Subject {
    api::Subject {
        id: subject.id,
        kind: subject_kind(subject.kind),
        state: match subject.state {
            SubjectState::Active => api::SubjectState::Active,
            SubjectState::Disabled => api::SubjectState::Disabled,
        },
        created_at: subject.created_at,
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
