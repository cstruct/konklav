use chrono::{DateTime, Utc};
use konklav_core::SubjectId;
use serde::{Deserialize, Serialize};

use crate::Credential;

/// Whether a subject is a person or software.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Human,
    Service,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectState {
    Active,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Subject {
    pub id: SubjectId,
    pub kind: SubjectKind,
    pub state: SubjectState,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SubjectQuery {
    pub kind: Option<SubjectKind>,
    /// A login identifier (email address, phone number or key id).
    pub identifier: Option<String>,
    pub before: Option<SubjectId>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubjectPage {
    pub subjects: Vec<Subject>,
    #[schema(required)]
    pub next: Option<SubjectId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateSubject {
    pub kind: SubjectKind,
}

/// A subject with its credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubjectDetail {
    #[serde(flatten)]
    pub subject: Subject,
    pub credentials: Vec<Credential>,
}
