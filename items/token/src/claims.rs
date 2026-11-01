use std::collections::BTreeMap;

use konklav_core::{MembershipId, SessionId, SubjectId, TenantId};
use serde::{Deserialize, Serialize};

/// What an access token may be used for.
// r[impl token.access.kind]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    /// The first factor succeeded but MFA is still required.
    Partial,
    /// Authenticated, no tenant selected.
    Identity,
    /// Targets one membership in one tenant.
    Tenant,
    ResetPassword,
    Invite,
}

/// The subject (and tenant) actually acting when a token is issued for
/// impersonation or assumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub sub: SubjectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<TenantId>,
}

/// The claims of a Konklav access token. Times are Unix seconds.
// r[impl token.access.standard-claims]
// r[impl token.access.session-claims]
// r[impl token.access.no-grants]
// r[impl item.token.shared-claims]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub aud: String,
    pub sub: SubjectId,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub knd: TokenKind,
    pub sid: SessionId,
    /// The credential the session was established with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<konklav_core::CredentialId>,
    /// The session version the token was issued at.
    pub sv: i64,
    pub amr: Vec<String>,
    pub auth_time: i64,
    // r[impl token.access.tenant-claims]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<TenantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mid: Option<MembershipId>,
    // r[impl token.access.flags]
    #[serde(default)]
    pub sfl: Vec<String>,
    // r[impl token.access.facts]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fct: BTreeMap<String, serde_json::Value>,
    // r[impl token.access.actor-chain]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
}
