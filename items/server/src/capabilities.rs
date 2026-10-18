//! Built-in control-plane capabilities, granted through global roles.

use conclave_authz::compile;
use conclave_core::SubjectId;
use conclave_store::{Connection, compile_input};

use crate::error::{ApiError, ErrorCode};

pub const IMPERSONATE: &str = "conclave:subject:impersonate";
pub const CONTROL_ALL: &str = "conclave:control:all";
pub const SUBJECTS: &str = "conclave:subjects:manage";
pub const TENANTS: &str = "conclave:tenants:manage";
pub const AUTHZ: &str = "conclave:authz:manage";
pub const SESSIONS: &str = "conclave:sessions:manage";
pub const KEYS: &str = "conclave:keys:manage";
pub const INVITES: &str = "conclave:invites:manage";
pub const IMPORT: &str = "conclave:import";
pub const CLIENTS: &str = "conclave:clients:manage";
pub const DELIVERY_READ: &str = "conclave:delivery:read";

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
