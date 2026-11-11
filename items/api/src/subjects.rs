use chrono::{DateTime, Utc};
use konklav_core::SubjectId;
use serde::{Deserialize, Serialize};

use crate::{Credential, Membership, RoleAssignment, Session};

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
    /// Final: the subject's personal data was removed, and only its id,
    /// kind and this state are left.
    Erased,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Subject {
    pub id: SubjectId,
    pub kind: SubjectKind,
    pub state: SubjectState,
    /// An object, opaque to Konklav.
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    /// Changes whenever `metadata` does; send it as `If-Match` to patch
    /// the metadata only if no one else has since.
    pub metadata_etag: String,
    pub created_at: DateTime<Utc>,
    /// When the subject was erased, if it was.
    #[schema(required)]
    pub erased_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SubjectQuery {
    pub kind: Option<SubjectKind>,
    /// A login identifier (email address, phone number or key id).
    pub identifier: Option<String>,
    /// A JSON object of strings, numbers and booleans: only objects whose
    /// metadata has each of its keys at the top level with an equal value.
    pub metadata: Option<String>,
    pub before: Option<SubjectId>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubjectPage {
    pub subjects: Vec<Subject>,
    #[schema(required)]
    pub next: Option<SubjectId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateSubject {
    pub kind: SubjectKind,
    /// An object, opaque to Konklav.
    #[serde(default = "crate::metadata::empty_object")]
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
}

/// A subject with its credentials and MFA factors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubjectDetail {
    #[serde(flatten)]
    pub subject: Subject,
    pub credentials: Vec<Credential>,
    /// Without their seeds.
    #[serde(default)]
    #[schema(required)]
    pub mfa_factors: Vec<MfaFactor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MfaFactorKind {
    Totp,
    EmailCode,
}

/// An MFA factor as the control plane shows it: never its seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MfaFactor {
    pub id: uuid::Uuid,
    pub kind: MfaFactorKind,
    /// Whether it has been activated; only active factors count towards a
    /// credential's `mfa_factors_required`.
    pub active: bool,
    /// The address an email-code factor sends to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    /// When it was removed. Only a personal data report shows removed
    /// factors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<DateTime<Utc>>,
}

/// Everything Konklav holds about one subject, without secrets: no password
/// hashes, secret keys, MFA seeds, passkey key material, refresh-token
/// hashes or challenge material.
///
/// For an erased subject every list is empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PersonalDataReport {
    pub subject: Subject,
    /// Revoked ones included.
    pub credentials: Vec<Credential>,
    /// Removed ones included.
    pub mfa_factors: Vec<MfaFactor>,
    /// Ended ones included.
    pub memberships: Vec<Membership>,
    /// Global assignments and those of the subject's memberships.
    pub role_assignments: Vec<RoleAssignment>,
    /// Every session not yet deleted by retention, newest first.
    pub sessions: Vec<Session>,
    /// Challenges not yet deleted by retention: those made for the subject,
    /// and those sent to one of its addresses without naming a subject.
    pub challenges: Vec<ReportedChallenge>,
    /// Attempts to log in with one of the subject's login identifiers or
    /// MFA factors, until the rate-limit window passes.
    pub login_attempts: Vec<ReportedLoginAttempt>,
}

/// A challenge in a personal data report, without its material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReportedChallenge {
    pub id: uuid::Uuid,
    /// What it was for, such as `email_link` or `invite`.
    pub purpose: String,
    /// The address it was sent to. Empty for a challenge that was not sent
    /// anywhere.
    pub recipient: String,
    /// What a relying system stored on an invite; empty for other
    /// challenges.
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[schema(required)]
    pub consumed_at: Option<DateTime<Utc>>,
    #[schema(required)]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A login attempt in a personal data report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReportedLoginAttempt {
    /// The kind of credential or MFA factor tried.
    pub kind: String,
    /// The login identifier tried, or the id of an MFA factor.
    pub identifier: String,
    pub succeeded: bool,
    pub attempted_at: DateTime<Utc>,
    /// The client address it came from, when one was recorded.
    #[schema(required)]
    pub address: Option<String>,
}
