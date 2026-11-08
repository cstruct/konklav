//! CORS for the OpenID provider's endpoints that browser apps call
//! directly: discovery and the key set from anywhere, and the token,
//! revocation and userinfo endpoints from the origins public clients
//! redirect to. Everything else on the subject-facing surface is
//! called first-party, and gets no CORS headers.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use konklav_store::oidc_clients::{self, ClientKind};

use crate::AppState;

/// What a public client's browser app sends besides the CORS-safelisted
/// headers: a bearer token at userinfo, and a proof of possession.
const ALLOWED_HEADERS: &str = "authorization, content-type, dpop";
/// What it may read besides the CORS-safelisted response headers.
const EXPOSED_HEADERS: &str = "www-authenticate, dpop-nonce";
const MAX_AGE: &str = "600";

/// The handler for `OPTIONS` on the routes these layers wrap, so a
/// preflight reaches the layer rather than the 405 fallback. The layer
/// answers allowed preflights itself; others get this, without CORS
/// headers.
pub(crate) async fn preflight() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Lets any origin read a public document, such as discovery or the key set.
// r[impl oidc.provider.cors]
pub(crate) async fn public(request: Request, next: Next) -> Response {
    if request.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(MAX_AGE),
        );
        return response;
    }
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// Lets the origins of active public clients' redirect URIs call the
/// endpoint. Requests from other origins pass through without CORS headers,
/// so the browser keeps their answers from the page.
// r[impl oidc.provider.cors]
pub(crate) async fn clients(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(origin) = request.headers().get(header::ORIGIN).cloned() else {
        return next.run(request).await;
    };
    if !allowed(&state, &origin).await {
        return next.run(request).await;
    }
    if request.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        let headers = response.headers_mut();
        allow(headers, origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(ALLOWED_HEADERS),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(MAX_AGE),
        );
        return response;
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    allow(headers, origin);
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSED_HEADERS),
    );
    response
}

fn allow(headers: &mut HeaderMap, origin: HeaderValue) {
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.append(header::VARY, HeaderValue::from_static("origin"));
}

/// Whether `origin` is the origin of a redirect URI of an active public
/// client. A lookup that fails allows nothing.
async fn allowed(state: &AppState, origin: &HeaderValue) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Ok(mut conn) = state.pool.get().await else {
        return false;
    };
    let Ok(clients) = oidc_clients::list(&mut conn, None).await else {
        return false;
    };
    clients
        .iter()
        .filter(|client| client.is_active() && client.kind == ClientKind::Public)
        .flat_map(|client| &client.redirect_uris)
        .any(|uri| origin_of(uri).is_some_and(|o| o.eq_ignore_ascii_case(origin)))
}

/// The origin a browser sends for pages at `uri`: its scheme, host and any
/// port, without userinfo, path or query.
fn origin_of(uri: &str) -> Option<String> {
    let uri: Uri = uri.parse().ok()?;
    let scheme = uri.scheme_str()?;
    let host = uri.host()?;
    Some(match uri.port_u16() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

#[cfg(test)]
mod tests {
    use super::origin_of;

    #[test]
    fn origins_drop_userinfo_paths_and_queries() {
        assert_eq!(
            origin_of("https://app.example/callback?x=1").as_deref(),
            Some("https://app.example")
        );
        assert_eq!(
            origin_of("http://user@localhost:5173/cb").as_deref(),
            Some("http://localhost:5173")
        );
        assert_eq!(origin_of("com.example.app:/callback"), None);
    }
}
