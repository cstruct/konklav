//! What evaluating a route's policy can end in, other than an allow, and
//! the mistakes in setting routes up that make it fail closed.

use std::fmt::{self, Write as _};

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use konklav_authz::{DenyReason, StepUp};
use konklav_relying::policy::PolicyError;
use konklav_relying_client::rate_limit::RateLimited;
use serde_json::{Value, json};

use crate::rate_limit::TemplateError;

/// The authorization scheme a token was presented with, to challenge a
/// refused one in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Bearer,
    DPoP,
}

impl Scheme {
    pub(crate) fn of(authorization: &str) -> Self {
        let scheme = authorization.split(' ').next().unwrap_or_default();
        if scheme.eq_ignore_ascii_case("dpop") {
            Self::DPoP
        } else {
            Self::Bearer
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::DPoP => "DPoP",
        }
    }
}

/// Why a request has no usable token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unauthenticated {
    /// No token was presented.
    MissingToken,
    /// The token doesn't verify, or its session has ended or moved on.
    InvalidToken,
    /// The DPoP proof or the authorization scheme was refused.
    InvalidDpopProof,
}

impl Unauthenticated {
    fn code(self) -> &'static str {
        match self {
            Self::MissingToken => "missing_token",
            Self::InvalidToken => "invalid_token",
            Self::InvalidDpopProof => "invalid_dpop_proof",
        }
    }
}

/// Why a request is forbidden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Forbidden {
    /// The decision's deny reason.
    Decision(DenyReason),
    /// The route's tenant isn't the token's (`item.axum.token-tenant`).
    TokenTenant,
}

/// A request the route's policy, or a rate limit, doesn't allow.
// r[impl item.axum.outcomes]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denied {
    /// 401: no usable token. A refused token is challenged in the scheme it
    /// was presented with, a refused proof with `DPoP`, and a missing token
    /// with both.
    Unauthenticated {
        reason: Unauthenticated,
        scheme: Option<Scheme>,
    },
    /// 403: a deny, carrying its reason.
    Forbidden(Forbidden),
    /// 401: fresher or stronger authentication would allow the request,
    /// challenged in the token's scheme as RFC 9470 says.
    StepUpRequired { requirement: StepUp, scheme: Scheme },
    /// 503: no decision could be reached, so the request is denied.
    Unavailable,
    /// 429: a rate limit refused the request.
    RateLimited { retry_after_ms: u64 },
}

impl Denied {
    /// The status the default answer has.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthenticated { .. } | Self::StepUpRequired { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    /// The code the default answer's body names.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated { reason, .. } => reason.code(),
            Self::Forbidden(_) => "forbidden",
            Self::StepUpRequired { .. } => "step_up",
            Self::Unavailable => "konklav_unavailable",
            Self::RateLimited { .. } => "rate_limited",
        }
    }

    /// The default answer's JSON body.
    #[must_use]
    pub fn body(&self) -> Value {
        match self {
            Self::Forbidden(reason) => {
                // As Konklav writes deny reasons: a bare code, or the code
                // with its fields.
                let reason = match reason {
                    Forbidden::Decision(reason) => {
                        serde_json::to_value(reason).unwrap_or(Value::Null)
                    }
                    Forbidden::TokenTenant => json!("token_tenant"),
                };
                json!({"error": {"code": "forbidden", "reason": reason}})
            }
            Self::StepUpRequired { requirement, .. } => json!({"error": {
                "code": "step_up",
                "requirement": serde_json::to_value(requirement).unwrap_or(Value::Null),
            }}),
            _ => json!({"error": {"code": self.code()}}),
        }
    }

    /// The default answer's `WWW-Authenticate` challenge, if it has one.
    #[must_use]
    pub fn challenge(&self) -> Option<String> {
        match self {
            Self::Unauthenticated {
                reason: Unauthenticated::InvalidDpopProof,
                ..
            } => Some(r#"DPoP error="invalid_dpop_proof""#.to_owned()),
            Self::Unauthenticated { scheme: None, .. } => Some("Bearer, DPoP".to_owned()),
            Self::Unauthenticated {
                reason,
                scheme: Some(scheme),
            } => Some(format!(r#"{} error="{}""#, scheme.as_str(), reason.code())),
            Self::StepUpRequired {
                requirement,
                scheme,
            } => {
                let mut challenge = format!(
                    r#"{} error="insufficient_user_authentication""#,
                    scheme.as_str()
                );
                if let Some(max_age) = requirement.max_age_seconds {
                    let _ = write!(challenge, ", max_age={max_age}");
                }
                Some(challenge)
            }
            _ => None,
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "denied: {}", self.code())
    }
}

impl std::error::Error for Denied {}

impl From<RateLimited> for Denied {
    fn from(limited: RateLimited) -> Self {
        Self::RateLimited {
            retry_after_ms: limited.retry_after_ms,
        }
    }
}

/// The `Retry-After` value for a wait of `retry_after_ms`: whole seconds,
/// rounded up, plus random jitter of up to a tenth of it (at least a
/// second), so clients refused together don't all retry together.
#[must_use]
pub fn retry_after_seconds(retry_after_ms: u64) -> u64 {
    let seconds = retry_after_ms.div_ceil(1000).max(1);
    let spread = (seconds / 10).max(1) + 1;
    seconds + getrandom::u64().unwrap_or(0) % spread
}

// r[impl item.axum.respond-with]
impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        let mut response = (self.status(), Json(self.body())).into_response();
        if let Some(challenge) = self.challenge()
            && let Ok(value) = HeaderValue::from_str(&challenge)
        {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        // r[impl item.axum.rate-limited]
        if let Self::RateLimited { retry_after_ms } = self {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(retry_after_seconds(retry_after_ms)),
            );
        }
        response
    }
}

/// Routes whose policies can't be evaluated: found when a [`RoutePolicy`]
/// is built, or, for what depends on the matched route or the
/// configuration, when a request meets it (then answered with 500).
///
/// [`RoutePolicy`]: crate::RoutePolicy
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutePolicyError {
    /// The route policies don't merge, or merge into one that denies every
    /// request.
    Policy(PolicyError),
    /// A router's route policy admits flags; only the route's own can.
    AdmitFlagsOutsideRoute,
    /// A rate-limit template is malformed.
    Template(TemplateError),
    /// A rate limit's key can't be rendered on the route.
    RateLimit { name: String, problem: String },
    /// No [`Konklav`](crate::Konklav) is installed on the router.
    NotInstalled,
    /// A second [`RoutePolicy`](crate::RoutePolicy) met a request one had
    /// already evaluated.
    Twice,
    /// The route's policy needs a scope kind with neither a resolver nor a
    /// path parameter of its name.
    MissingScope { kind: String },
    /// A token extractor on a route without a route policy.
    NoPolicy { extractor: &'static str },
    /// A token extractor that doesn't take every kind the route's policy
    /// admits, or that isn't `OptionalToken` on a public route.
    Extractor {
        extractor: &'static str,
        problem: String,
    },
    /// A request without a peer address, for its client address.
    NoClientAddress,
}

impl fmt::Display for RoutePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => error.fmt(f),
            Self::AdmitFlagsOutsideRoute => f.write_str(
                "admit_flags set outside the route; only the route's own route policy can admit flags",
            ),
            Self::Template(error) => error.fmt(f),
            Self::RateLimit { name, problem } => write!(f, "rate limit `{name}` {problem}"),
            Self::NotInstalled => f.write_str(
                "route policies need Konklav installed on the router: .layer(konklav.layer())",
            ),
            Self::Twice => f.write_str(
                "a second RoutePolicy met the request; give each route one RoutePolicy",
            ),
            Self::MissingScope { kind } => write!(
                f,
                "needs a `{kind}` scope: configure a scope resolver or add a `{kind}` path parameter"
            ),
            Self::NoPolicy { extractor } => {
                write!(f, "{extractor} on a route without a RoutePolicy")
            }
            Self::Extractor { extractor, problem } => write!(f, "{extractor} {problem}"),
            Self::NoClientAddress => f.write_str(
                "the request has no peer address for its client address; serve with into_make_service_with_connect_info::<SocketAddr>()",
            ),
        }
    }
}

impl std::error::Error for RoutePolicyError {}

impl From<PolicyError> for RoutePolicyError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<TemplateError> for RoutePolicyError {
    fn from(error: TemplateError) -> Self {
        Self::Template(error)
    }
}

// r[impl item.axum.misconfiguration]
impl IntoResponse for RoutePolicyError {
    fn into_response(self) -> Response {
        tracing::error!(problem = %self, "route set up wrongly; denying");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": {"code": "route_policy_error"}})),
        )
            .into_response()
    }
}
