//! Batches: several control-plane operations in one request, applied in
//! one transaction. Each operation runs through the control-plane router
//! itself, so it is routed, guarded, parsed and answered exactly as it
//! would be alone; only its database connection differs, the batch's,
//! handed out by [`Db`](crate::db::Db).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use diesel_async::{AsyncConnection, TransactionManager};
use konklav_api::{Batch, BatchMethod, BatchOperation, BatchResult, BatchResults, ErrorResponse};
use konklav_store::{Connection, events};
use tokio::sync::Mutex;
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::control_api::Written;
use crate::db::Shared;
use crate::error::{ApiError, ApiJson, ErrorCode};
use crate::{AppState, error};

type Transactions = <Connection as AsyncConnection>::TransactionManager;

/// A response that ends a batch: its own error or a failed operation's.
type Failure = Box<Response>;

// Boxed here so callers can `map_err(fail)?`.
#[allow(clippy::unnecessary_box_returns)]
fn fail(error: impl Into<ApiError>) -> Failure {
    Box::new(error.into().into_response())
}

/// How large batches may be and how long their idempotency keys are kept
/// (`[control]` in the configuration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchLimits {
    pub max_operations: usize,
    pub key_lifetime: Duration,
    pub max_key_lifetime: Duration,
}

impl BatchLimits {
    pub const DEFAULT: Self = Self {
        max_operations: 100,
        key_lifetime: Duration::from_secs(600),
        max_key_lifetime: Duration::from_secs(3600),
    };
}

/// The batch route, described like the other control-plane routes.
pub(crate) fn batch() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(apply_batch))
}

/// The control-plane routes a batch's operations run through: every one
/// but the batch itself.
#[derive(Clone)]
pub(crate) struct Dispatch(pub(crate) Router);

/// Applies operations in order, all or nothing.
///
/// Each operation is a `PUT`, `POST` or `DELETE` with the path (without
/// `/v1`) and body it takes alone, and is authorized against the caller's own
/// capabilities. On success, `results` holds what each answered; on failure
/// nothing is committed and the error is the failing operation's, with its
/// position as `error.operation`.
// r[impl platform.batch.atomic]
// r[impl platform.batch.same-as-alone]
// r[impl platform.batch.failure]
#[utoipa::path(post, path = "/batch", operation_id = "apply_batch", tag = "batch",
    request_body = Batch,
    responses((status = 200, description = "Every operation was applied", body = Written<BatchResults>)))]
async fn apply_batch(
    State(state): State<AppState>,
    Extension(Dispatch(router)): Extension<Dispatch>,
    headers: HeaderMap,
    ApiJson(batch): ApiJson<Batch>,
) -> Response {
    match run(&state, router, &headers, batch.operations).await {
        Ok(written) => Json(written).into_response(),
        Err(failure) => *failure,
    }
}

/// Checks the operations against the limits before anything runs.
// r[impl platform.batch.limits]
// r[impl platform.batch.operations]
fn check(state: &AppState, operations: &[BatchOperation]) -> Result<(), ApiError> {
    let max = state.auth.batches.max_operations;
    if operations.is_empty() {
        return Err(ApiError::invalid_request("a batch needs an operation"));
    }
    if operations.len() > max {
        return Err(ApiError::invalid_request(format!(
            "a batch holds at most {max} operations"
        )));
    }
    for (index, operation) in operations.iter().enumerate() {
        let path = operation.path.split('?').next().unwrap_or_default();
        if !path.starts_with('/') {
            return Err(ApiError::invalid_request(format!(
                "operation {index}'s path must start with /"
            )));
        }
        if path.trim_end_matches('/') == "/batch" {
            return Err(ApiError::invalid_request("a batch can't contain a batch"));
        }
    }
    Ok(())
}

async fn run(
    state: &AppState,
    router: Router,
    headers: &HeaderMap,
    operations: Vec<BatchOperation>,
) -> Result<Written<BatchResults>, Failure> {
    check(state, &operations).map_err(fail)?;
    let mut conn = state.pool.get().await.map_err(fail)?;
    Transactions::begin_transaction(&mut *conn)
        .await
        .map_err(fail)?;
    // If the request times out mid-batch, this future is dropped with the
    // transaction open; the pool discards a connection in that state rather
    // than reusing it.
    let shared = Shared(Arc::new(Mutex::new(conn)));
    let mut results = Vec::with_capacity(operations.len());
    let mut failure = None;
    for (index, operation) in operations.into_iter().enumerate() {
        match dispatch(&router, &shared, headers, operation).await {
            Ok(result) => results.push(result),
            Err(response) => {
                failure = Some(failed(index, *response).await);
                break;
            }
        }
    }
    let mut conn = shared.0.lock().await;
    if let Some(failure) = failure {
        // A failed rollback leaves the transaction open, so the pool
        // discards the connection.
        let _ = Transactions::rollback_transaction(&mut **conn).await;
        return Err(Box::new(failure));
    }
    let finish = async {
        let cursor = events::last_in_transaction(&mut conn).await?;
        Transactions::commit_transaction(&mut **conn).await?;
        Ok::<_, ApiError>(cursor)
    };
    match finish.await {
        Ok(cursor) => Ok(Written {
            value: BatchResults { results },
            cursor,
        }),
        Err(error) => {
            let _ = Transactions::rollback_transaction(&mut **conn).await;
            Err(fail(error))
        }
    }
}

/// Runs one operation through the router on the batch's connection.
/// Returns its result, or its response when it failed.
async fn dispatch(
    router: &Router,
    shared: &Shared,
    headers: &HeaderMap,
    operation: BatchOperation,
) -> Result<BatchResult, Failure> {
    let method = match operation.method {
        BatchMethod::Put => Method::PUT,
        BatchMethod::Post => Method::POST,
        BatchMethod::Delete => Method::DELETE,
    };
    let mut request = Request::builder().method(method).uri(&operation.path);
    if let Some(authorization) = headers.get(header::AUTHORIZATION) {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    let body = match &operation.body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(body).unwrap_or_default())
        }
        None => Body::empty(),
    };
    let mut request = request
        .body(body)
        .map_err(|_| fail(ApiError::invalid_request("not a valid path")))?;
    request.extensions_mut().insert(shared.clone());
    let response = match router.clone().oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    if !response.status().is_success() {
        return Err(Box::new(response));
    }
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|error| fail(ApiError::internal(error)))?;
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).map_err(|error| fail(ApiError::internal(error)))?
    };
    Ok(BatchResult { status, body })
}

/// The batch's answer for an operation that failed: its status, headers and
/// error, with its position added.
async fn failed(index: usize, response: Response) -> Response {
    let (mut parts, body) = response.into_parts();
    let error = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => serde_json::from_slice::<ErrorResponse>(&bytes).ok(),
        Err(_) => None,
    };
    let mut error = error.unwrap_or_else(|| {
        let code = parts
            .extensions
            .get::<ErrorCode>()
            .copied()
            .unwrap_or(ErrorCode::Internal);
        ErrorResponse {
            error: konklav_api::ErrorBody {
                code,
                message: "the operation failed".into(),
                operation: None,
            },
        }
    });
    error.error.operation = Some(index);
    parts.headers.remove(header::CONTENT_LENGTH);
    let status: StatusCode = parts.status;
    let mut response = (status, Json(error)).into_response();
    for (name, value) in &parts.headers {
        if name != header::CONTENT_TYPE {
            response.headers_mut().insert(name, value.clone());
        }
    }
    response.extensions_mut().extend(parts.extensions);
    response
}

/// The routes a batch dispatches into, with the control surface's
/// fallbacks so an unknown path or method fails like it would alone.
pub(crate) fn dispatch_router(routes: Router<AppState>, state: &AppState) -> Router {
    routes
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .with_state(state.clone())
}
