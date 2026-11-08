use http::StatusCode;
use serde::{Deserialize, Serialize};

/// Stable, machine-readable error codes. Never rename a variant: add a new
/// one instead.
// r[impl platform.error.typed-codes]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    NotFound,
    MethodNotAllowed,
    InvalidRequest,
    Conflict,
    /// An `If-Match` precondition didn't hold: the object changed since
    /// its entity tag was read.
    PreconditionFailed,
    /// The write would leave an object's metadata over the size limit.
    MetadataTooLarge,
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
    /// The claims hook failed and is configured to refuse userinfo then.
    ClaimsHookUnavailable,
    Internal,
    DatabaseUnavailable,
    MigrationsPending,
}

impl ErrorCode {
    /// The HTTP status every response with this code has.
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::InvalidRequest | Self::MetadataTooLarge => StatusCode::BAD_REQUEST,
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unauthenticated | Self::InvalidCredentials | Self::SessionEnded => {
                StatusCode::UNAUTHORIZED
            }
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Overloaded
            | Self::SigningKeyUnavailable
            | Self::ClaimsHookUnavailable
            | Self::DatabaseUnavailable
            | Self::MigrationsPending => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// The body of every error response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorBody {
    pub code: ErrorCode,
    /// For humans; it may change between releases.
    pub message: String,
    /// For a failed batch: the failing operation's position, from zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<usize>,
}
