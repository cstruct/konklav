//! Conclave's error envelope, as the console sees it.

use std::fmt;

use serde::Deserialize;
use serde::de::DeserializeOwned;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// Conclave answered with an error.
    Api {
        status: u16,
        code: String,
        message: String,
    },
    /// The request didn't get an answer.
    Network(String),
    /// The answer wasn't what the console expected.
    Decode(String),
}

#[derive(Deserialize)]
struct Envelope {
    error: Body,
}

#[derive(Deserialize)]
struct Body {
    code: String,
    message: String,
}

impl ApiError {
    /// Reads `{"error": {"code", "message"}}`, or describes the status when
    /// something in between (a proxy, say) answered instead.
    #[must_use]
    pub fn from_response(status: u16, body: &str) -> Self {
        match serde_json::from_str::<Envelope>(body) {
            Ok(Envelope { error }) => Self::Api {
                status,
                code: error.code,
                message: error.message,
            },
            Err(_) => Self::Api {
                status,
                code: format!("HTTP_{status}"),
                message: if body.trim().is_empty() {
                    format!("HTTP {status}")
                } else {
                    body.trim().chars().take(200).collect()
                },
            },
        }
    }

    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } => Some(code),
            Self::Network(_) | Self::Decode(_) => None,
        }
    }

    /// The capability a control-plane refusal names.
    ///
    /// ```
    /// use konklav_console::api::ApiError;
    /// let error = ApiError::from_response(
    ///     403,
    ///     r#"{"error":{"code":"FORBIDDEN","message":"missing capability konklav:keys:manage"}}"#,
    /// );
    /// assert_eq!(error.missing_capability(), Some("konklav:keys:manage"));
    /// ```
    #[must_use]
    pub fn missing_capability(&self) -> Option<&str> {
        match self {
            Self::Api { code, message, .. } if code == "FORBIDDEN" => {
                message.strip_prefix("missing capability ")
            }
            _ => None,
        }
    }

    /// Whether the access token no longer works, so the console should
    /// refresh or sign the operator out.
    #[must_use]
    pub fn ends_session(&self) -> bool {
        matches!(self.code(), Some("UNAUTHENTICATED" | "SESSION_ENDED"))
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api { code, message, .. } => write!(f, "{message} ({code})"),
            Self::Network(message) => write!(f, "Conclave is unreachable: {message}"),
            Self::Decode(message) => write!(f, "unexpected response: {message}"),
        }
    }
}

/// Turns a response into `T`, or into the error it carries.
pub fn decode<T: DeserializeOwned>(status: u16, body: &str) -> Result<T, ApiError> {
    if !(200..300).contains(&status) {
        return Err(ApiError::from_response(status, body));
    }
    let body = if body.trim().is_empty() { "null" } else { body };
    serde_json::from_str(body).map_err(|error| ApiError::Decode(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_error_envelope() {
        let error = ApiError::from_response(
            401,
            r#"{"error":{"code":"SESSION_ENDED","message":"the session has ended"}}"#,
        );
        assert_eq!(error.code(), Some("SESSION_ENDED"));
        assert!(error.ends_session());
        assert_eq!(error.missing_capability(), None);
        assert_eq!(error.to_string(), "the session has ended (SESSION_ENDED)");
    }

    #[test]
    fn describes_answers_without_an_envelope() {
        let error = ApiError::from_response(502, "");
        assert_eq!(error.code(), Some("HTTP_502"));
        assert!(!error.ends_session());
    }

    #[test]
    fn other_refusals_name_no_capability() {
        let error = ApiError::from_response(
            403,
            r#"{"error":{"code":"FORBIDDEN","message":"complete MFA first"}}"#,
        );
        assert_eq!(error.missing_capability(), None);
    }

    #[test]
    fn decodes_successes_and_empty_bodies() {
        assert_eq!(decode::<u32>(200, "7"), Ok(7));
        assert_eq!(decode::<Option<u32>>(204, ""), Ok(None));
        assert!(matches!(decode::<u32>(200, "{"), Err(ApiError::Decode(_))));
        assert_eq!(
            decode::<u32>(
                404,
                r#"{"error":{"code":"NOT_FOUND","message":"subject not found"}}"#
            )
            .unwrap_err()
            .code(),
            Some("NOT_FOUND")
        );
    }
}
