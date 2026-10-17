//! Liveness and readiness checks, served on every listener.

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::AppState;
use crate::error::{ApiError, ErrorCode};

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Status {
    pub status: &'static str,
}

/// Liveness: the process is up and serving requests.
// r[impl platform.server.health]
pub async fn healthz() -> Json<Status> {
    Json(Status { status: "ok" })
}

/// Readiness: the database answers and no migrations are pending.
pub async fn readyz(State(state): State<AppState>) -> Result<Json<Status>, ApiError> {
    conclave_store::ping(&state.pool).await.map_err(|error| {
        tracing::warn!(%error, "readiness: database unavailable");
        ApiError::new(
            ErrorCode::DatabaseUnavailable,
            "the database is unavailable",
        )
    })?;
    let pending = conclave_store::pending_migrations(&state.pool)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "readiness: could not check migrations");
            ApiError::new(ErrorCode::DatabaseUnavailable, "could not check migrations")
        })?;
    if !pending.is_empty() {
        return Err(ApiError::new(
            ErrorCode::MigrationsPending,
            format!("{} migration(s) pending", pending.len()),
        ));
    }
    Ok(Json(Status { status: "ready" }))
}
