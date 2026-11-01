//! Bulk import of identity data from a system Konklav replaces: subjects,
//! pre-hashed credentials, MFA seeds and sessions, keyed by their existing
//! ids so imports can be re-run. The records and how they are written live
//! in [`crate::import`].
//!
//! Tenants, memberships, the catalog, templates, roles and assignments are
//! imported through the ordinary (idempotent) control-plane endpoints.

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use diesel_async::AsyncConnection;
use serde::{Deserialize, Serialize};

use crate::control_api::guard;
use crate::error::{ApiError, ApiJson};
use crate::import::{self, CredentialRecord, FactorRecord, Outcome, SessionRecord, SubjectRecord};
use crate::{AppState, capabilities};

pub fn routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/import/subjects", post(import_subjects))
        .route("/import/credentials", post(import_credentials))
        .route("/import/mfa-factors", post(import_factors))
        .route("/import/sessions", post(import_sessions))
        .route_layer(guard(state, capabilities::IMPORT))
}

// The field names are the API's.
#[allow(clippy::struct_field_names)]
#[derive(Serialize, Default)]
struct Imported {
    imported: usize,
    skipped: usize,
    /// Existing secret keys whose slots were replaced.
    updated: usize,
}

impl Imported {
    fn count(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Created => self.imported += 1,
            Outcome::Skipped => self.skipped += 1,
            Outcome::Updated => self.updated += 1,
        }
    }
}

#[derive(Deserialize)]
struct Subjects {
    subjects: Vec<SubjectRecord>,
}

/// `POST /v1/import/subjects`
async fn import_subjects(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Subjects>,
) -> Result<Json<Imported>, ApiError> {
    let mut conn = state.pool.get().await?;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in &body.subjects {
                result.count(import::subject(conn, record).await?);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
struct Credentials {
    credentials: Vec<CredentialRecord>,
}

/// `POST /v1/import/credentials`
async fn import_credentials(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Credentials>,
) -> Result<Json<Imported>, ApiError> {
    let mut conn = state.pool.get().await?;
    let records = body.credentials;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in records {
                result.count(import::credential(conn, record).await?);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
struct Factors {
    factors: Vec<FactorRecord>,
}

/// `POST /v1/import/mfa-factors`: TOTP seeds arrive in plaintext over the
/// control plane and are encrypted before the transaction opens.
async fn import_factors(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Factors>,
) -> Result<Json<Imported>, ApiError> {
    let mut prepared = Vec::with_capacity(body.factors.len());
    for record in body.factors {
        let data = import::seal_factor(&state.auth.secrets, record.id, record.material)?;
        prepared.push((record.id, record.subject, data, record.active));
    }
    let mut conn = state.pool.get().await?;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for (id, subject, data, active) in &prepared {
                result.count(import::factor(conn, *id, *subject, data, *active).await?);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
struct Sessions {
    sessions: Vec<SessionRecord>,
}

/// `POST /v1/import/sessions`
async fn import_sessions(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<Sessions>,
) -> Result<Json<Imported>, ApiError> {
    let mut conn = state.pool.get().await?;
    let records = body.sessions;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in records {
                result.count(import::session(conn, record).await?);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}
