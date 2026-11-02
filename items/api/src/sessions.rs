use chrono::{DateTime, Utc};
use konklav_core::{CredentialId, MembershipId, SessionId, SubjectId, TenantId};
use serde::{Deserialize, Serialize};

/// How far a session has got: `partial` until MFA completes, `identity`
/// without a tenant, `tenant` with one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionStage {
    Partial,
    Identity,
    Tenant,
}

/// Whether the session's refresh token travels in a cookie or in bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Browser,
    Native,
}

/// Single claims an OIDC client asked for with the `claims` request
/// parameter.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RequestedClaims {
    #[serde(default)]
    pub userinfo: Vec<String>,
    #[serde(default)]
    pub id_token: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Session {
    pub id: SessionId,
    pub subject_id: SubjectId,
    pub credential_id: CredentialId,
    pub tenant_id: Option<TenantId>,
    pub membership_id: Option<MembershipId>,
    pub stage: SessionStage,
    pub client_kind: ClientKind,
    pub amr: Vec<String>,
    pub auth_time: DateTime<Utc>,
    pub flags: Vec<String>,
    pub impersonator_subject_id: Option<SubjectId>,
    /// MFA factors verified in this session.
    pub mfa_factors: Vec<String>,
    /// The session this one was started from (impersonation); ending the
    /// parent ends this one.
    pub parent_session_id: Option<SessionId>,
    /// The OIDC client the session was started for, if any.
    pub oidc_client_id: Option<String>,
    /// The scopes granted to that client.
    pub oidc_scopes: Vec<String>,
    /// Single claims the client asked for, beyond its scopes' claims.
    pub oidc_claims: RequestedClaims,
    /// Claims passed from the identity provider the session was started
    /// through, by scope, until the session ends.
    #[schema(value_type = Option<Object>)]
    pub identity_claims: Option<serde_json::Value>,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_reason: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SessionQuery {
    pub subject: Option<SubjectId>,
    pub credential: Option<CredentialId>,
    /// Only sessions neither revoked nor expired.
    #[serde(default)]
    pub active: bool,
    pub before: Option<SessionId>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SessionPage {
    pub sessions: Vec<Session>,
    /// Pass as `before` to get the next page.
    pub next: Option<SessionId>,
}

/// Which sessions to act on. Every set field must match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SessionFilter {
    pub session: Option<SessionId>,
    pub subject: Option<SubjectId>,
    pub credential: Option<CredentialId>,
    pub tenant: Option<TenantId>,
    pub membership: Option<MembershipId>,
}

/// Revokes the sessions a filter matches; it must set at least one field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RevokeSessions {
    #[serde(flatten)]
    pub filter: SessionFilter,
    /// A session to leave alone even if it matches.
    pub keep: Option<SessionId>,
    /// Recorded as the revocation reason; `revoked_by_operator` when absent.
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RevokedSessions {
    pub revoked: Vec<SessionId>,
}
