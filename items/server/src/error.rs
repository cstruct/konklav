//! The typed error model shared by every surface.
//!
//! Error responses always have the shape
//! `{"error": {"code": "SCREAMING_SNAKE_CASE", "message": "..."}}`. Clients
//! rely on `code`; `message` is for humans and may change.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Stable, machine-readable error codes. Never rename a variant: add a new
/// one instead.
// r[impl platform.error.typed-codes]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    NotFound,
    MethodNotAllowed,
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
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseUnavailable | Self::MigrationsPending => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
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
        (self.code.status(), Json(body)).into_response()
    }
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
