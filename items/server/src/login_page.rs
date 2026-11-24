//! The login page built into the server: a login application for Konklav's
//! OpenID provider (see `items/login`), served by the subject-facing surface
//! at `/login/` from files embedded at build time.
//!
//! The page uses only the public `/v1` API, from Konklav's own origin. What
//! the server adds is the files, with headers that keep them from being
//! framed, inlined into or leaked through the `Referer`, and `config.json`,
//! which tells the page which sign-in methods are configured.

use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Serialize;

use crate::AppState;
use crate::config::{BrowserConfig, Tokens};
use crate::error::ApiError;

/// One embedded file, by its path under `/login/`.
pub(crate) struct Asset {
    path: &'static str,
    bytes: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/login_page.rs"));

/// Where the page is served, relative to a listener's root.
pub const PATH: &str = "/login/";

/// Whether this binary holds the page's build, rather than nothing (built
/// without the `login-page` feature) or a placeholder (built without the
/// page's files).
#[must_use]
pub fn built() -> bool {
    BUILT
}

/// Whether this binary can serve the page at all.
#[must_use]
pub fn available() -> bool {
    !FILES.is_empty()
}

/// The login page's settings, built once at startup.
#[derive(Clone, Debug, Serialize)]
pub struct LoginPage {
    pub title: String,
    pub passkeys: bool,
    /// Identity providers to offer, in configuration order.
    pub identity_providers: Vec<ProviderLink>,
    /// The page's own URL, which identity providers return to.
    pub return_to: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderLink {
    pub id: String,
    pub name: String,
}

impl LoginPage {
    /// The page's URL for an issuer: `{issuer}/login/`.
    #[must_use]
    pub fn url(issuer: &str) -> String {
        format!("{}{PATH}", issuer.trim_end_matches('/'))
    }

    /// Prepares `browser` for the page, when it is configured: the issuer's
    /// origin, which serves the page, may use browser sign-in, and every
    /// identity provider may return to the page. Returns the page's
    /// settings.
    ///
    /// # Errors
    ///
    /// When the page is configured but this binary can't serve it, when
    /// `browser` isn't configured, or when the issuer isn't a URL.
    // r[impl oidc.provider.login-page]
    pub fn configure(tokens: &Tokens, browser: &mut BrowserConfig) -> Result<Option<Self>, String> {
        let Some(page) = browser.login_page.as_ref().filter(|page| page.enabled) else {
            return Ok(None);
        };
        if !available() {
            return Err(
                "login_page is configured, but this server was built without the `login-page` \
                 feature"
                    .into(),
            );
        }
        if !built() {
            tracing::warn!("serving a placeholder login page: this server was built without it");
        }
        let title = page.title.clone().unwrap_or_else(|| "Sign in".into());
        let origin = origin(&tokens.issuer)
            .ok_or_else(|| format!("tokens.issuer `{}` is not an http(s) URL", tokens.issuer))?;
        let Some(settings) = browser.browser.as_mut() else {
            return Err("login_page needs browser sign-in: configure `browser`".into());
        };
        // Passkeys work on the page only if its host is within the relying
        // party ID. Where it isn't, passkey origins that default to the
        // allowed origins keep the ones configured, and the page offers no
        // passkeys.
        let mut passkeys = false;
        if let Some(config) = browser.passkeys.as_mut() {
            let host = reqwest::Url::parse(&origin)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_default();
            passkeys = host == config.rp_id || host.ends_with(&format!(".{}", config.rp_id));
            if config.origins.is_empty() && !passkeys {
                config.origins.clone_from(&settings.allowed_origins);
            } else if !config.origins.is_empty() && passkeys && !config.origins.contains(&origin) {
                config.origins.push(origin.clone());
            }
        }
        if !settings.allowed_origins.contains(&origin) {
            settings.allowed_origins.push(origin);
        }
        let return_to = Self::url(&tokens.issuer);
        let mut identity_providers = Vec::new();
        for provider in &mut browser.identity_providers {
            if !provider.return_urls.contains(&return_to) {
                provider.return_urls.push(return_to.clone());
            }
            identity_providers.push(ProviderLink {
                id: provider.id.clone(),
                name: provider.name.clone().unwrap_or_else(|| provider.id.clone()),
            });
        }
        Ok(Some(Self {
            title,
            passkeys,
            identity_providers,
            return_to,
        }))
    }
}

/// `scheme://host[:port]` of a URL, as browsers send it in `Origin`.
fn origin(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

/// The page's routes, for the subject-facing surface's root.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(to_directory))
        .route("/login/", get(index))
        .route("/login/config.json", get(config))
        .route("/login/{*path}", get(file))
        .layer(middleware::from_fn(headers))
}

/// `/login` to `/login/`, so the page's relative references resolve, with
/// the query (the login request) kept.
async fn to_directory(uri: Uri) -> Redirect {
    Redirect::permanent(&match uri.query() {
        Some(query) => format!("{PATH}?{query}"),
        None => PATH.to_owned(),
    })
}

fn find(path: &str) -> Option<&'static Asset> {
    FILES.iter().find(|asset| asset.path == path)
}

async fn index() -> Response {
    find("index.html").map_or_else(not_found, |asset| serve(asset, false))
}

async fn file(Path(path): Path<String>) -> Response {
    match find(&path) {
        // Vite names its assets by their content's hash.
        Some(asset) => serve(asset, path.starts_with("assets/")),
        None => not_found(),
    }
}

/// What `config.json` holds: the page's settings, and whether people may
/// request access to the tenant a client asks for.
#[derive(Serialize)]
struct PageConfig<'a> {
    #[serde(flatten)]
    page: &'a LoginPage,
    access_requests: bool,
}

/// `GET /login/config.json`: what the page offers. Read on every load, so
/// never cached.
// r[impl oidc.provider.login-page.access-requests]
async fn config(State(state): State<AppState>) -> Response {
    match &state.auth.login_page {
        Some(page) => (
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            axum::Json(PageConfig {
                page,
                access_requests: state.auth.access_requests.is_some(),
            }),
        )
            .into_response(),
        None => not_found(),
    }
}

fn serve(asset: &'static Asset, immutable: bool) -> Response {
    let cache = if immutable {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(asset.path)),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
        ],
        asset.bytes,
    )
        .into_response()
}

fn not_found() -> Response {
    ApiError::not_found("file").into_response()
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// The page may run only its own scripts and styles, talk only to its own
/// origin, and never be framed. `no-referrer`, since the address holds the
/// login request.
// r[impl oidc.provider.login-page.headers]
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; \
     base-uri 'none'";

// r[impl oidc.provider.login-page.headers]
async fn headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let missing = response.status() == StatusCode::NOT_FOUND;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (
            header::HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    if missing {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_what_browsers_send() {
        assert_eq!(
            origin("https://id.example/").as_deref(),
            Some("https://id.example")
        );
        assert_eq!(
            origin("http://127.0.0.1:8080").as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            origin("https://id.example:443/tenant").as_deref(),
            Some("https://id.example")
        );
        assert_eq!(origin("urn:konklav"), None);
    }

    #[test]
    fn the_page_is_under_the_issuer() {
        assert_eq!(
            LoginPage::url("https://id.example"),
            "https://id.example/login/"
        );
        assert_eq!(
            LoginPage::url("https://id.example/"),
            "https://id.example/login/"
        );
    }

    #[test]
    fn index_is_embedded() {
        assert!(find("index.html").is_some() || !available());
    }
}
