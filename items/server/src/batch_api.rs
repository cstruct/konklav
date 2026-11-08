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
use chrono::{DateTime, Utc};
use diesel_async::{AsyncConnection, TransactionManager};
use konklav_api::{Batch, BatchMethod, BatchOperation, BatchResult, BatchResults, ErrorResponse};
use konklav_store::batch_results::{self, Remembered};
use konklav_store::{Connection, events};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::capabilities::Operator;
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
/// Each operation is a `PUT`, `POST`, `PATCH` or `DELETE` with the path (without
/// `/v1`) and body it takes alone, and is authorized against the caller's own
/// capabilities. On success, `results` holds what each answered; on failure
/// nothing is committed and the error is the failing operation's, with its
/// position as `error.operation`. With an `idempotency_key`, repeating the
/// batch answers what it first answered, with new secrets where that answer
/// showed some.
// r[impl platform.batch.atomic]
// r[impl platform.batch.same-as-alone]
// r[impl platform.batch.failure]
#[utoipa::path(post, path = "/batch", operation_id = "apply_batch", tag = "batch",
    request_body = Batch,
    responses((status = 200, description = "Every operation was applied, now or by the first batch with the same idempotency key", body = Written<BatchResults>)))]
async fn apply_batch(
    State(state): State<AppState>,
    Extension(Dispatch(router)): Extension<Dispatch>,
    Extension(operator): Extension<Operator>,
    headers: HeaderMap,
    ApiJson(batch): ApiJson<Batch>,
) -> Response {
    match apply(&state, &router, operator, &headers, batch).await {
        Ok(written) => Json(written).into_response(),
        Err(failure) => *failure,
    }
}

async fn apply(
    state: &AppState,
    router: &Router,
    operator: Operator,
    headers: &HeaderMap,
    batch: Batch,
) -> Result<Written<BatchResults>, Failure> {
    check(state, &batch.operations).map_err(fail)?;
    let positions: Vec<usize> = (0..batch.operations.len()).collect();
    let Some(key) = Idempotency::of(state, operator, &batch).map_err(fail)? else {
        let ran = run(state, router, headers, batch.operations, &positions, None).await?;
        return ran.ok_or_else(|| fail(ApiError::internal("a batch without a key raced")));
    };
    if let Some(found) = lookup(state, &key).await? {
        return replay(state, router, headers, &key, found).await;
    }
    match run(
        state,
        router,
        headers,
        batch.operations,
        &positions,
        Some(&key),
    )
    .await?
    {
        Some(written) => Ok(written),
        // A concurrent batch with the key committed first.
        None => {
            let found = lookup(state, &key)
                .await?
                .ok_or_else(|| fail(ApiError::internal("a remembered batch went missing")))?;
            replay(state, router, headers, &key, found).await
        }
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

/// A batch's idempotency key, whose it is, and what it was sent with.
struct Idempotency {
    caller: String,
    key: String,
    request_hash: Vec<u8>,
    expires_at: DateTime<Utc>,
}

impl Idempotency {
    // r[impl platform.batch.key-lifetime]
    fn of(state: &AppState, operator: Operator, batch: &Batch) -> Result<Option<Self>, ApiError> {
        let Some(key) = &batch.idempotency_key else {
            if batch.idempotency_seconds.is_some() {
                return Err(ApiError::invalid_request(
                    "idempotency_seconds needs an idempotency_key",
                ));
            }
            return Ok(None);
        };
        if key.is_empty() || key.chars().count() > 255 {
            return Err(ApiError::invalid_request(
                "an idempotency key has 1 to 255 characters",
            ));
        }
        let limits = state.auth.batches;
        let lifetime = match batch.idempotency_seconds {
            None => limits.key_lifetime,
            Some(seconds) => {
                let asked = Duration::from_secs(u64::from(seconds));
                if seconds == 0 || asked > limits.max_key_lifetime {
                    return Err(ApiError::invalid_request(format!(
                        "idempotency_seconds must be between 1 and {}",
                        limits.max_key_lifetime.as_secs()
                    )));
                }
                asked
            }
        };
        let operations = serde_json::to_vec(&batch.operations).map_err(ApiError::internal)?;
        Ok(Some(Self {
            caller: operator.caller(),
            key: key.clone(),
            request_hash: Sha256::digest(&operations).to_vec(),
            expires_at: Utc::now()
                + chrono::Duration::from_std(lifetime).map_err(ApiError::internal)?,
        }))
    }
}

/// What a batch with a key leaves behind: its answer without the secrets it
/// showed, and the operations that showed them, to run again on a repeat.
#[derive(Serialize, Deserialize)]
struct Stored {
    answer: Written<BatchResults>,
    reruns: Vec<Rerun>,
}

#[derive(Serialize, Deserialize)]
struct Rerun {
    index: usize,
    operation: BatchOperation,
}

/// Fields of operation results that hold secrets shown only once: a
/// secret key's, an OIDC client's and a link-only invite's token.
// r[impl authn.invite.link-only]
const SECRETS: [&str; 4] = ["secret_keys", "secret_key", "client_secret", "token"];

impl Stored {
    fn of(operations: &[BatchOperation], answer: &Written<BatchResults>) -> Self {
        let mut answer = answer.clone();
        let mut reruns = Vec::new();
        for (index, (operation, result)) in
            operations.iter().zip(&mut answer.value.results).enumerate()
        {
            let mut shown = false;
            for field in SECRETS {
                if let Some(secret) = result.body.get_mut(field)
                    && !secret.is_null()
                {
                    *secret = serde_json::Value::Null;
                    shown = true;
                }
            }
            if !shown {
                continue;
            }
            let mut operation = operation.clone();
            // A credential or invite created without an id is created again
            // under the one it got, which shows new secrets for it.
            let id = result.body["credential"]
                .get("id")
                .or_else(|| result.body.get("invite_id"));
            if let (Some(serde_json::Value::Object(body)), Some(id)) = (&mut operation.body, id) {
                body.entry("id").or_insert_with(|| id.clone());
            }
            reruns.push(Rerun { index, operation });
        }
        Self { answer, reruns }
    }
}

async fn lookup(state: &AppState, key: &Idempotency) -> Result<Option<Remembered>, Failure> {
    let mut conn = state.pool.get().await.map_err(fail)?;
    batch_results::get(&mut conn, &key.caller, &key.key, Utc::now())
        .await
        .map_err(fail)
}

/// The first answer for a repeated batch, with new secrets where it showed
/// some.
// r[impl platform.batch.idempotency-key]
async fn replay(
    state: &AppState,
    router: &Router,
    headers: &HeaderMap,
    key: &Idempotency,
    found: Remembered,
) -> Result<Written<BatchResults>, Failure> {
    if found.request_hash != key.request_hash {
        return Err(fail(ApiError::new(
            ErrorCode::Conflict,
            "the idempotency key was used for other operations",
        )));
    }
    let Stored { mut answer, reruns } =
        serde_json::from_value(found.answer).map_err(|error| fail(ApiError::internal(error)))?;
    if reruns.is_empty() {
        return Ok(answer);
    }
    let positions: Vec<usize> = reruns.iter().map(|rerun| rerun.index).collect();
    let operations = reruns.into_iter().map(|rerun| rerun.operation).collect();
    let rerun = run(state, router, headers, operations, &positions, None)
        .await?
        .ok_or_else(|| fail(ApiError::internal("a rerun without a key raced")))?;
    for (index, result) in positions.into_iter().zip(rerun.value.results) {
        let first = &mut answer.value.results[index].body;
        for field in SECRETS {
            if let Some(secret) = result.body.get(field) {
                first[field] = secret.clone();
            }
        }
    }
    Ok(answer)
}

/// Runs `operations` in one transaction and commits them, remembering the
/// answer under `key` if given. `positions` are the operations' places in
/// the batch the caller sent, for failures. `None` when a concurrent batch
/// remembered `key` first, in which case nothing is committed.
async fn run(
    state: &AppState,
    router: &Router,
    headers: &HeaderMap,
    operations: Vec<BatchOperation>,
    positions: &[usize],
    key: Option<&Idempotency>,
) -> Result<Option<Written<BatchResults>>, Failure> {
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
    for (operation, &position) in operations.iter().zip(positions) {
        match dispatch(router, &shared, headers, operation.clone()).await {
            Ok(result) => results.push(result),
            Err(response) => {
                failure = Some(failed(position, *response).await);
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
        let written = Written {
            value: BatchResults { results },
            cursor: events::last_in_transaction(&mut conn).await?,
        };
        if let Some(key) = key {
            let stored = serde_json::to_value(Stored::of(&operations, &written))
                .map_err(ApiError::internal)?;
            let remembered = Remembered {
                request_hash: key.request_hash.clone(),
                answer: stored,
            };
            let now = Utc::now();
            if !batch_results::remember(
                &mut conn,
                &key.caller,
                &key.key,
                &remembered,
                now,
                key.expires_at,
            )
            .await?
            {
                return Ok(None);
            }
        }
        Ok::<_, ApiError>(Some(written))
    };
    match finish.await {
        Ok(Some(written)) => match Transactions::commit_transaction(&mut **conn).await {
            Ok(()) => Ok(Some(written)),
            Err(error) => {
                let _ = Transactions::rollback_transaction(&mut **conn).await;
                Err(fail(error))
            }
        },
        Ok(None) => {
            let _ = Transactions::rollback_transaction(&mut **conn).await;
            Ok(None)
        }
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
        BatchMethod::Patch => Method::PATCH,
        BatchMethod::Delete => Method::DELETE,
    };
    let mut request = Request::builder().method(method).uri(&operation.path);
    if let Some(authorization) = headers.get(header::AUTHORIZATION) {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    if let Some(tag) = &operation.if_match {
        let value = if tag.starts_with('"') || tag == "*" {
            tag.clone()
        } else {
            format!("\"{tag}\"")
        };
        request = request.header(header::IF_MATCH, value);
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
