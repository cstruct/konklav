//! DPoP proofs at the OpenID provider's endpoints (RFC 9449). Verification
//! itself is `konklav_token::verify_proof`; this module finds the proof,
//! builds the URL it must name, and records its `jti`.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use konklav_store::Connection;
use konklav_token::{Proof, ProofRequest};

use crate::AppState;
use crate::error::ApiError;
use crate::oidc_api::endpoint;

/// How far in the future a proof's `iat` may be, for client clock skew.
const LEEWAY_SECONDS: i64 = 5;

/// The `algs` a DPoP challenge lists.
const CHALLENGE: &str = "DPoP algs=\"ES256 EdDSA\"";

/// What a proof check is made against.
pub(crate) struct Expected<'a> {
    pub method: &'a str,
    /// The endpoint under `/v1/oauth2/`, such as `token`.
    pub endpoint: &'a str,
    pub access_token: Option<&'a str>,
    pub bound_to: Option<&'a str>,
}

/// The request's DPoP proof, if it has exactly one `DPoP` header.
fn header_value(headers: &HeaderMap) -> Result<Option<&str>, &'static str> {
    let mut values = headers.get_all("dpop").iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(value), None) => value
            .to_str()
            .map(Some)
            .map_err(|_| "the DPoP header is malformed"),
        (Some(_), Some(_)) => Err("send one DPoP header"),
    }
}

/// Verifies the request's DPoP proof, if it carries one, and records its
/// `jti` so it can't be used again. `Ok(Err(reason))` means the proof was
/// refused.
// r[impl oidc.provider.dpop.htu]
// r[impl token.dpop.replay]
pub(crate) async fn check(
    state: &AppState,
    conn: &mut Connection,
    headers: &HeaderMap,
    expected: &Expected<'_>,
) -> Result<Result<Option<Proof>, &'static str>, ApiError> {
    let proof = match header_value(headers) {
        Ok(Some(proof)) => proof,
        Ok(None) => return Ok(Ok(None)),
        Err(reason) => return Ok(Err(reason)),
    };
    let max_age = state
        .auth
        .oidc
        .as_ref()
        .map_or(60, |provider| provider.dpop_max_age);
    // The URL discovery publishes, never the request's `Host`.
    let url = endpoint(state, expected.endpoint);
    let request = ProofRequest {
        method: expected.method,
        url: &url,
        access_token: expected.access_token,
        bound_to: expected.bound_to,
        now: Utc::now().timestamp(),
        max_age,
        leeway: LEEWAY_SECONDS,
    };
    let proof = match konklav_token::verify_proof(proof, &request) {
        Ok(proof) => proof,
        Err(error) => {
            tracing::info!(%error, endpoint = expected.endpoint, "DPoP proof refused");
            return Ok(Err("the DPoP proof is invalid"));
        }
    };
    let until =
        chrono::DateTime::from_timestamp(proof.replayable_until(max_age) + LEEWAY_SECONDS, 0)
            .unwrap_or_else(Utc::now);
    if !konklav_store::dpop_proofs::record(conn, &proof.jkt, &proof.jti, until).await? {
        return Ok(Err("the DPoP proof was already used"));
    }
    Ok(Ok(Some(proof)))
}

/// A token request refused for its DPoP proof.
// r[impl oidc.provider.dpop.errors]
pub(crate) fn invalid_token_request(description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({
            "error": "invalid_dpop_proof",
            "error_description": description,
        })),
    )
        .into_response()
}

/// A resource request refused for its DPoP proof or scheme: 401 with a
/// DPoP challenge.
// r[impl oidc.provider.dpop.errors]
pub(crate) fn invalid_resource_request(description: &str) -> Response {
    let mut response =
        ApiError::new(crate::error::ErrorCode::Unauthenticated, description).into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("DPoP error=\"invalid_dpop_proof\", algs=\"ES256 EdDSA\""),
    );
    response
}

/// The DPoP challenge offered next to the bearer one on other 401s.
pub(crate) fn challenge() -> HeaderValue {
    HeaderValue::from_static(CHALLENGE)
}
