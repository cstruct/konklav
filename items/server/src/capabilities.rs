//! Built-in control-plane capabilities, granted through global roles.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use conclave_authz::compile;
use conclave_core::SubjectId;
use conclave_store::sessions::Stage;
use conclave_store::{Connection, compile_input};
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
    let input = compile_input::load(&mut conn, claims.sub, None).await?;
    let capabilities = compile(&input.catalog, &input.assignments)
        .global
        .into_iter()
        .filter(|action| action.starts_with("konklav:"))
        .collect();
    Ok(Json(OwnCapabilities {
        subject: claims.sub,
        capabilities,
    }))
}
