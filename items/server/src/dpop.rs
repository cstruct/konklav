//! DPoP proofs (RFC 9449) at the OpenID provider's endpoints and on
//! Konklav's own surfaces. Verification itself is
//! `konklav_token::verify_proof`; this module finds the proof, works out
//! the URLs it may name, and records its `jti`.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
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
    /// The URLs the proof may name; it must name one of them.
    pub urls: Vec<String>,
    pub access_token: Option<&'a str>,
    pub bound_to: Option<&'a str>,
}

impl Expected<'_> {
    /// The URL of an OpenID provider endpoint under `/v1/oauth2/`, as
    /// discovery publishes it.
    // r[impl oidc.provider.dpop.htu]
    pub(crate) fn endpoint(state: &AppState, path: &str) -> Vec<String> {
        vec![endpoint(state, path)]
    }
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
    // Configured URLs, never the request's `Host`.
    let mut verified = Err(konklav_token::ProofError::WrongUrl);
    for url in &expected.urls {
        let request = ProofRequest {
            method: expected.method,
            url,
            access_token: expected.access_token,
            bound_to: expected.bound_to,
            now: Utc::now().timestamp(),
            max_age,
            leeway: LEEWAY_SECONDS,
        };
        verified = konklav_token::verify_proof(proof, &request);
        if verified != Err(konklav_token::ProofError::WrongUrl) {
            break;
        }
    }
    let proof = match verified {
        Ok(proof) => proof,
        Err(error) => {
            tracing::info!(%error, "DPoP proof refused");
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

/// The key of a valid DPoP proof that came with a request without an
/// access token, such as a login or a cookie refresh: the session it starts
/// or refreshes is bound to it. Set by [`own_surfaces`].
#[derive(Clone, Debug)]
struct Binding(String);

/// The key thumbprint a request's binding proof named, if it had one: what
/// a session-starting handler binds its session to.
#[derive(Clone, Debug, Default)]
pub(crate) struct Bound(pub Option<String>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Bound {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let bound = parts
            .extensions
            .get::<Binding>()
            .map(|binding| binding.0.clone());
        std::future::ready(Ok(Self(bound)))
    }
}

/// The client endpoints of the OpenID provider, which check their proofs
/// themselves and take client tokens.
const PROVIDER_ENDPOINTS: [&str; 3] = [
    "/v1/oauth2/token",
    "/v1/oauth2/userinfo",
    "/v1/oauth2/revoke",
];

/// The URLs a proof for `path` on Konklav's own surfaces may name: each
/// base URL followed by the path.
// r[impl session.dpop.surfaces]
fn own_urls(state: &AppState, path: &str) -> Vec<String> {
    own_bases(state)
        .iter()
        .map(|base| format!("{}{path}", base.trim_end_matches('/')))
        .collect()
}

/// The configured `tokens.dpop_urls`, or by default the issuer and each
/// allowed browser origin, also with the `/control` prefix under which a
/// console reaches the control plane (`r[item.console.same-origin]`), so a
/// console works without more configuration.
fn own_bases(state: &AppState) -> Vec<String> {
    if !state.auth.dpop_urls.is_empty() {
        return state.auth.dpop_urls.clone();
    }
    let origins = state
        .auth
        .browser
        .iter()
        .flat_map(|browser| &browser.allowed_origins)
        .flat_map(|origin| {
            let origin = origin.trim_end_matches('/');
            [origin.to_owned(), format!("{origin}/control")]
        });
    std::iter::once(state.auth.issuer.clone())
        .chain(origins)
        .collect()
}

/// DPoP for Konklav's own tokens on the subject-facing and control-plane
/// surfaces:
///
/// - under `DPoP`, the proof is verified against the token, and the
///   handlers then see a plain bearer token
/// - under `Bearer`, a sender-constrained token is refused
/// - without a token, a `DPoP` header is verified as a binding proof, which
///   session-starting handlers and the cookie refresh find as [`Binding`]
///
/// Tokens for other audiences (OIDC clients') and the provider's client
/// endpoints are left alone.
// r[impl session.dpop.surfaces]
// r[impl token.dpop.scheme]
pub(crate) async fn own_surfaces(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    if PROVIDER_ENDPOINTS.contains(&path.as_str()) {
        return next.run(request).await;
    }
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .map(|(scheme, token)| (scheme.to_ascii_lowercase(), token.trim().to_owned()));
    let own = |token: &str| {
        konklav_token::decode_claims_unverified(token)
            .filter(|claims| claims.aud == state.auth.audience)
    };
    let method = request.method().as_str().to_owned();
    let urls = own_urls(&state, &path);
    match presented {
        Some((scheme, token)) if scheme == "dpop" => {
            let Some(claims) = own(&token) else {
                return next.run(request).await;
            };
            let Some(cnf) = claims.cnf else {
                return invalid_resource_request("the access token isn't DPoP-bound");
            };
            let expected = Expected {
                method: &method,
                urls,
                access_token: Some(&token),
                bound_to: Some(&cnf.jkt),
            };
            match checked(&state, request.headers(), &expected).await {
                Ok(Ok(Some(_))) => {}
                Ok(Ok(None)) => return invalid_resource_request("a DPoP proof is required"),
                Ok(Err(reason)) => return invalid_resource_request(reason),
                Err(error) => return error.into_response(),
            }
            // The handlers authenticate bearer tokens; this one is proven.
            match HeaderValue::from_str(&format!("Bearer {token}")) {
                Ok(bearer) => {
                    request.headers_mut().insert(header::AUTHORIZATION, bearer);
                }
                Err(_) => return invalid_resource_request("the access token is malformed"),
            }
        }
        Some((scheme, token)) if scheme == "bearer" => {
            if own(&token).is_some_and(|claims| claims.cnf.is_some()) {
                return invalid_resource_request(
                    "the access token is DPoP-bound; use the DPoP scheme",
                );
            }
        }
        None if request.headers().contains_key("dpop") => {
            let expected = Expected {
                method: &method,
                urls,
                access_token: None,
                bound_to: None,
            };
            match checked(&state, request.headers(), &expected).await {
                Ok(Ok(Some(proof))) => {
                    request.extensions_mut().insert(Binding(proof.jkt));
                }
                Ok(Ok(None)) => {}
                Ok(Err(reason)) => return invalid_resource_request(reason),
                Err(error) => return error.into_response(),
            }
        }
        Some(_) | None => {}
    }
    next.run(request).await
}

async fn checked(
    state: &AppState,
    headers: &HeaderMap,
    expected: &Expected<'_>,
) -> Result<Result<Option<Proof>, &'static str>, ApiError> {
    let mut conn = state.pool.get().await?;
    check(state, &mut conn, headers, expected).await
}
