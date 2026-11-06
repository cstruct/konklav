//! The login application, on <http://localhost:8000>.
//!
//! Konklav has no user interface: its authorization endpoint hands the
//! browser to this login page, which signs the person in through
//! Konklav's own API and accepts the request (`web/sso/login.js`). The
//! Konklav session is bound to the page's DPoP key, and its refresh token
//! is an `HttpOnly` cookie: the single sign-on.
//!
//! This process serves the page and proxies Konklav's subject-facing
//! surface (`/v1`, `/.well-known`), so the cookie, the page and Konklav's
//! issuer share one origin.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use konklav_sso_example::web::{self, LOGIN_HTML, LOGIN_JS};
use konklav_sso_example::{env, serve};

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Hop-by-hop headers, and ones the HTTP client recomputes.
const SKIPPED: [HeaderName; 6] = [
    header::HOST,
    header::CONNECTION,
    header::TRANSFER_ENCODING,
    header::CONTENT_LENGTH,
    header::CONTENT_ENCODING,
    header::UPGRADE,
];

#[derive(Clone)]
struct Proxy {
    http: reqwest::Client,
    konklav: String,
}

/// Passes a request to Konklav as is, and its answer back, cookies and
/// redirects included.
async fn proxy(State(proxy): State<Proxy>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, 1 << 20).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let mut headers = parts.headers;
    for name in &SKIPPED {
        headers.remove(name);
    }
    let upstream = proxy
        .http
        .request(parts.method, format!("{}{path}", proxy.konklav))
        .headers(headers)
        .body(body)
        .send()
        .await;
    let Ok(upstream) = upstream else {
        return (StatusCode::BAD_GATEWAY, "Konklav is unreachable").into_response();
    };
    let status = upstream.status();
    let mut headers = upstream.headers().clone();
    for name in &SKIPPED {
        headers.remove(name);
    }
    let body = upstream.bytes().await.unwrap_or_default();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[tokio::main]
async fn main() {
    let state = Proxy {
        // Redirects go back to the browser, never followed here.
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("an HTTP client"),
        konklav: env("KONKLAV_SUBJECT_URL"),
    };
    let router = Router::new()
        .route("/", get(|| async { web::page(LOGIN_HTML, CSP) }))
        .route("/login", get(|| async { web::page(LOGIN_HTML, CSP) }))
        .route("/static/login.js", get(|| async { web::script(LOGIN_JS) }))
        .merge(web::shared())
        .route("/v1/{*path}", axum::routing::any(proxy))
        .route("/.well-known/{*path}", axum::routing::any(proxy))
        .route("/readyz", get(proxy))
        .with_state(state);
    serve(router, 8000).await;
}
