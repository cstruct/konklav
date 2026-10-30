//! The typed error model shared by every surface.
//!
//! Error responses always have the shape
//! `{"error": {"code": "SCREAMING_SNAKE_CASE", "message": "..."}}`. Clients
//! rely on `code`; `message` is for humans and may change.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, OptionalFromRequest, Request};
use axum::http::StatusCode;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use konklav_store::{PoolError, StoreError};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Stable, machine-readable error codes. Never rename a variant: add a new
/// one instead.
// r[impl platform.error.typed-codes]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    NotFound,
    MethodNotAllowed,
    InvalidRequest,
    Conflict,
    /// No usable credentials were presented (missing or invalid token).
    Unauthenticated,
    /// The login identifier, secret or credential is wrong. Deliberately
    /// says nothing about which.
    InvalidCredentials,
    /// The session behind a token or refresh token has ended.
    SessionEnded,
    Forbidden,
    RateLimited,
    /// The server is serving too many requests, or this one took too long.
    Overloaded,
    SigningKeyUnavailable,
    Internal,
    DatabaseUnavailable,
    MigrationsPending,
}

impl ErrorCode {
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unauthenticated | Self::InvalidCredentials | Self::SessionEnded => {
                StatusCode::UNAUTHORIZED
            }
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Overloaded
            | Self::SigningKeyUnavailable
            | Self::DatabaseUnavailable
            | Self::MigrationsPending => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, message)
    }

    #[must_use]
    pub fn not_found(what: &str) -> Self {
        Self::new(ErrorCode::NotFound, format!("{what} not found"))
    }

    /// Logs the cause and hides it from the client.
    #[must_use]
    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(%error, "internal error");
        Self::new(ErrorCode::Internal, "internal error")
    }
}

#[derive(Serialize)]
struct Envelope<'a> {
    error: Body<'a>,
}

#[derive(Serialize)]
struct Body<'a> {
    code: ErrorCode,
    message: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Envelope {
            error: Body {
                code: self.code,
                message: &self.message,
            },
        };
        let mut response = (self.code.status(), Json(body)).into_response();
        // For telemetry, which records the code.
        response.extensions_mut().insert(self.code);
        if self.code == ErrorCode::RateLimited {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, retry_after().into());
        }
        response
    }
}

/// Seconds a rate-limited client should wait: a minute plus up to 30
/// seconds of jitter, so clients refused together don't all retry together.
// r[impl platform.error.retry-after]
fn retry_after() -> u32 {
    const BASE: u32 = 60;
    const JITTER: u32 = 30;
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("system randomness");
    BASE + u32::from_le_bytes(bytes) % (JITTER + 1)
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => Self::new(ErrorCode::NotFound, "not found"),
            StoreError::Conflict(message) => Self::new(ErrorCode::Conflict, message),
            StoreError::Reserved(message) => Self::new(ErrorCode::InvalidRequest, message),
            StoreError::Database(error) => Self::internal(error),
        }
    }
}

impl From<PoolError> for ApiError {
    fn from(error: PoolError) -> Self {
        tracing::warn!(%error, "database unavailable");
        Self::new(
            ErrorCode::DatabaseUnavailable,
            "the database is unavailable",
        )
    }
}

impl From<diesel::result::Error> for ApiError {
    fn from(error: diesel::result::Error) -> Self {
        Self::internal(error)
    }
}

impl From<konklav_store::Checkout> for ApiError {
    fn from(error: konklav_store::Checkout) -> Self {
        PoolError::from(error).into()
    }
}

/// A JSON body whose rejections are typed `INVALID_REQUEST` errors.
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match <Json<T> as FromRequest<S>>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection(&rejection)),
        }
    }
}

/// An optional JSON body: absent when the request has no body, typed
/// `INVALID_REQUEST` when it has one that doesn't parse.
impl<T, S> OptionalFromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        let empty = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|length| length == "0");
        if empty || !req.headers().contains_key(header::CONTENT_TYPE) {
            return Ok(None);
        }
        <Self as FromRequest<S>>::from_request(req, state)
            .await
            .map(Some)
    }
}

fn json_rejection(rejection: &JsonRejection) -> ApiError {
    ApiError::invalid_request(rejection.body_text())
}

/// Answers requests that match no route.
pub async fn not_found() -> ApiError {
    ApiError::new(ErrorCode::NotFound, "no such endpoint")
}

/// Answers requests to a known path with an unsupported method.
pub async fn method_not_allowed() -> ApiError {
    ApiError::new(
        ErrorCode::MethodNotAllowed,
        "method not allowed on this endpoint",
    )
}
