//! Bulk import of identity data from a system Konklav replaces: subjects,
//! pre-hashed credentials, MFA seeds and sessions, keyed by their existing
//! ids so imports can be re-run. The records and how they are written live
//! in [`crate::import`].
//!
//! Tenants, memberships, the catalog, templates, roles and assignments are
//! imported through the ordinary (idempotent) control-plane endpoints.

use axum::Json;
use axum::extract::State;
use diesel_async::AsyncConnection;
use konklav_api::{ImportCredentials, ImportFactors, ImportSessions, ImportSubjects, Imported};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::db::Db;
use crate::error::{ApiError, ApiJson};
use crate::import::{self, Outcome};
use crate::{AppState, metadata, transport};

/// The import routes, with the `OpenAPI` description of each taken from
/// its handler's `#[utoipa::path]`.
pub(crate) fn import() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(import_subjects))
        .routes(routes!(import_credentials))
        .routes(routes!(import_factors))
        .routes(routes!(import_sessions))
}

fn count(result: &mut Imported, outcome: Outcome) {
    match outcome {
        Outcome::Created => result.imported += 1,
        Outcome::Skipped => result.skipped += 1,
        Outcome::Updated => result.updated += 1,
    }
}

/// Imports subjects.
///
/// Imports subjects from another system, all or nothing.
#[utoipa::path(post, path = "/import/subjects", tag = "import",
    request_body = ImportSubjects,
    responses((status = 200, body = Imported)))]
async fn import_subjects(
    db: Db,
    limit: metadata::Limit,
    ApiJson(body): ApiJson<ImportSubjects>,
) -> Result<Json<Imported>, ApiError> {
    for subject in &body.subjects {
        limit.check(&subject.metadata)?;
    }
    let records: Vec<_> = body
        .subjects
        .iter()
        .map(transport::subject_record)
        .collect();
    let mut conn = db.get().await?;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in &records {
                count(&mut result, import::subject(conn, record).await?);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

/// Imports credentials.
///
/// Imports credentials from another system, with their existing hashes or
/// secrets, all or nothing.
#[utoipa::path(post, path = "/import/credentials", tag = "import",
    request_body = ImportCredentials,
    responses((status = 200, body = Imported)))]
async fn import_credentials(
    db: Db,
    limit: metadata::Limit,
    ApiJson(body): ApiJson<ImportCredentials>,
) -> Result<Json<Imported>, ApiError> {
    for credential in &body.credentials {
        limit.check(&credential.metadata)?;
    }
    let mut conn = db.get().await?;
    let records = body
        .credentials
        .into_iter()
        .map(transport::credential_record);
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in records {
                count(&mut result, import::credential(conn, record).await?);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

/// Imports MFA factors.
///
/// TOTP seeds arrive in plaintext and are encrypted before they are stored. All
/// or nothing.
#[utoipa::path(post, path = "/import/mfa-factors", tag = "import",
    request_body = ImportFactors,
    responses((status = 200, body = Imported)))]
async fn import_factors(
    State(state): State<AppState>,
    db: Db,
    ApiJson(body): ApiJson<ImportFactors>,
) -> Result<Json<Imported>, ApiError> {
    let mut prepared = Vec::with_capacity(body.factors.len());
    for record in body.factors.into_iter().map(transport::factor_record) {
        let data = import::seal_factor(&state.auth.secrets, record.id, record.material)?;
        prepared.push((record.id, record.subject, data, record.active));
    }
    let mut conn = db.get().await?;
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for (id, subject, data, active) in &prepared {
                count(
                    &mut result,
                    import::factor(conn, *id, *subject, data, *active).await?,
                );
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}

/// Imports sessions.
///
/// Imports sessions from another system, all or nothing.
#[utoipa::path(post, path = "/import/sessions", tag = "import",
    request_body = ImportSessions,
    responses((status = 200, body = Imported)))]
async fn import_sessions(
    db: Db,
    ApiJson(body): ApiJson<ImportSessions>,
) -> Result<Json<Imported>, ApiError> {
    let mut conn = db.get().await?;
    let records = body.sessions.into_iter().map(transport::session_record);
    let result = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let mut result = Imported::default();
            for record in records {
                count(&mut result, import::session(conn, record).await?);
            }
            Ok(result)
        })
        .await?;
    Ok(Json(result))
}
