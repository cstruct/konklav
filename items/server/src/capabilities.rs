//! Built-in control-plane capabilities, granted through global roles.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use konklav_authz::{Effect, Policy, compile};
use konklav_core::SubjectId;
use konklav_store::catalog::CAPABILITY_PREFIX;
use konklav_store::roles::Role;
use konklav_store::sessions::Stage;
use konklav_store::{Connection, compile_input, templates};
use serde::Serialize;

use crate::AppState;
use crate::error::{ApiError, ErrorCode};
use crate::subject_api::authenticate;

pub const IMPERSONATE: &str = "konklav:subject:impersonate";
pub const CONTROL_ALL: &str = "konklav:control:all";
pub const SUBJECTS: &str = "konklav:subjects:manage";
pub const TENANTS: &str = "konklav:tenants:manage";
pub const AUTHZ: &str = "konklav:authz:manage";
pub const SESSIONS: &str = "konklav:sessions:manage";
pub const KEYS: &str = "konklav:keys:manage";
pub const INVITES: &str = "konklav:invites:manage";
pub const IMPORT: &str = "konklav:import";
pub const CLIENTS: &str = "konklav:clients:manage";
pub const DELIVERY_READ: &str = "konklav:delivery:read";
pub const SCOPES_REGISTER: &str = "konklav:scopes:register";

/// Whether `subject` holds `capability` through its global assignments.
// r[impl authz.control-plane.capability]
pub async fn holds(
    conn: &mut Connection,
    subject: SubjectId,
    capability: &str,
) -> Result<bool, ApiError> {
    let input = compile_input::load(conn, subject, None).await?;
    Ok(compile(&input.catalog, &input.assignments)
        .global
        .contains(capability))
}

/// Whether `policies` allow any control-plane capability. Capabilities
/// are only granted by name, never through groups.
#[must_use]
pub fn granted_by(policies: &[Policy]) -> bool {
    policies.iter().any(|policy| {
        policy.effect == Effect::Allow && policy.action.starts_with(CAPABILITY_PREFIX)
    })
}

/// Whether `role` allows any control-plane capability, through its own
/// policies or its template's.
pub async fn granted_by_role(conn: &mut Connection, role: &Role) -> Result<bool, ApiError> {
    if granted_by(&role.policies) {
        return Ok(true);
    }
    Ok(match &role.template {
        Some(key) => granted_by(&templates::get(conn, key).await?.policies),
        None => false,
    })
}

/// Whether `subject` holds any control-plane capability: an operator.
/// Compiles entitlements in a transaction of its own, so it can't run
/// inside another.
pub async fn held_by(conn: &mut Connection, subject: SubjectId) -> Result<bool, ApiError> {
    let input = compile_input::load(conn, subject, None).await?;
    Ok(compile(&input.catalog, &input.assignments)
        .global
        .iter()
        .any(|action| action.starts_with(CAPABILITY_PREFIX)))
}

/// What the control-plane guard learned about the caller, for handlers that
/// need more than the route's capability.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Operator {
    /// Holds `konklav:control:all`, or used the bootstrap token.
    pub(crate) all: bool,
    /// The operator's subject; `None` for the bootstrap token.
    pub(crate) subject: Option<SubjectId>,
}

impl Operator {
    /// Who is calling, as batches remember their idempotency keys by.
    pub(crate) fn caller(self) -> String {
        self.subject.map_or_else(
            || "bootstrap".to_owned(),
            |subject| format!("subject:{subject}"),
        )
    }

    /// Granting or withdrawing capabilities, and changing how an operator
    /// authenticates, need `konklav:control:all`: otherwise a narrower
    /// capability would be a path to every capability.
    // r[impl authz.control-plane.escalation]
    pub(crate) fn require_all(self, what: &str) -> Result<(), ApiError> {
        if self.all {
            Ok(())
        } else {
            Err(ApiError::new(
                ErrorCode::Forbidden,
                format!("{what} needs {CONTROL_ALL}"),
            ))
        }
    }

    /// [`Self::require_all`] if `subject` is an operator.
    pub(crate) async fn may_change(
        self,
        conn: &mut Connection,
        subject: SubjectId,
    ) -> Result<(), ApiError> {
        if self.all || !held_by(conn, subject).await? {
            return Ok(());
        }
        self.require_all("changing an operator's credentials or state")
    }
}

pub async fn require(
    conn: &mut Connection,
    subject: SubjectId,
    capability: &str,
) -> Result<(), ApiError> {
    if holds(conn, subject, capability).await? {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::Forbidden,
            format!("missing capability {capability}"),
        ))
    }
}

/// Subject-facing routes for reading one's own capabilities.
pub fn routes() -> Router<AppState> {
    Router::new().route("/capabilities", get(own_capabilities))
}

#[derive(Serialize)]
struct OwnCapabilities {
    subject: SubjectId,
    capabilities: Vec<String>,
}

/// `GET /v1/capabilities`: the control-plane capabilities the caller holds,
/// so operator tools can tell what they may do before trying it.
// r[impl authz.control-plane.own-capabilities]
async fn own_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OwnCapabilities>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (claims, session) = authenticate(&state, &mut conn, &headers).await?;
    if session.stage == Stage::Partial {
        return Err(ApiError::new(ErrorCode::Forbidden, "complete MFA first"));
    }
    // r[impl authn.impersonation.limits]
    let capabilities = if session.impersonator_subject_id.is_some() {
        Vec::new()
    } else {
        let input = compile_input::load(&mut conn, claims.sub, None).await?;
        compile(&input.catalog, &input.assignments)
            .global
            .into_iter()
            .filter(|action| action.starts_with("konklav:"))
            .collect()
    };
    Ok(Json(OwnCapabilities {
        subject: claims.sub,
        capabilities,
    }))
}
