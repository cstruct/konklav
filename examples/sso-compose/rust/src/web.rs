//! The browser files, shared with the Python version and compiled into the
//! binaries, and the headers pages are served with.

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

macro_rules! web {
    ($path:literal) => {
        include_str!(concat!("../../web/", $path))
    };
}

pub const LOGIN_HTML: &str = web!("sso/login.html");
pub const LOGIN_JS: &str = web!("sso/login.js");
pub const APP_HTML: &str = web!("app/index.html");
pub const APP_JS: &str = web!("app/app.js");
pub const ADMIN_HTML: &str = web!("admin/admin.html");
pub const ADMIN_JS: &str = web!("admin/admin.js");
const DPOP_JS: &str = web!("shared/dpop.js");
const STYLE_CSS: &str = web!("shared/style.css");

/// A page, with headers that suit it. A strict CSP matters most here: a
/// page whose tokens live in memory is only as safe as its scripts.
///
/// # Panics
///
/// If `csp` isn't a valid header value.
#[must_use]
pub fn page(html: &'static str, csp: &str) -> Response {
    let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
    let headers = response.headers_mut();
    for (name, value) in [
        ("content-security-policy", csp),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cache-control", "no-store"),
    ] {
        headers.insert(name, HeaderValue::from_str(value).expect("a valid header"));
    }
    response
}

/// A script.
#[must_use]
pub fn script(js: &'static str) -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        js,
    )
        .into_response()
}

/// `/shared/dpop.js` and `/shared/style.css`, which every page loads.
pub fn shared<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/shared/dpop.js", get(|| async { script(DPOP_JS) }))
        .route(
            "/shared/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    STYLE_CSS,
                )
            }),
        )
}
