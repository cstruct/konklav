use chrono::{DateTime, Utc};
use konklav_authz::Requirements;
use konklav_core::SessionId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExplainQuery {
    /// The tenant (a UUID or `root`); global roles only when absent.
    pub tenant: Option<String>,
    /// The action to explain.
    pub action: String,
}

/// A decision to explain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExplainDecision {
    /// The tenant to decide in; the session's when absent.
    #[serde(default)]
    pub tenant: Option<String>,
    /// One of the subject's sessions, to check authentication as its tokens
    /// would be checked.
    #[serde(default)]
    pub session: Option<SessionId>,
    #[serde(default)]
    pub requirements: Requirements,
    /// The time to explain the decision as of, as RFC 3339; now when
    /// absent. Needs history, and can't be combined with a session.
    #[serde(default)]
    pub at: Option<DateTime<Utc>>,
}
