//! The app's frontend, on <http://localhost:3000>: the page and its script
//! only. The page is a public OIDC client (`app`) that signs in with the
//! code flow, PKCE and DPoP and keeps its tokens in memory
//! (`web/app/app.js`).

use axum::routing::get;
use axum::{Json, Router};
use konklav_sso_example::web::{self, APP_HTML, APP_JS};
use konklav_sso_example::{env, serve};
use serde_json::json;

#[tokio::main]
async fn main() {
    let issuer = env("ISSUER");
    let api = env("API_URL");
    // Scripts only from this origin; fetches only to Konklav and the API.
    let csp = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' {issuer} {api}; base-uri 'none'; frame-ancestors 'none'"
    );
    let config = json!({"issuer": issuer, "client_id": env("CLIENT_ID"), "api": api});
    println!("{config}");

    let page = {
        let csp = csp.clone();
        move || async move { web::page(APP_HTML, &csp) }
    };
    let router = Router::new()
        .route("/", get(page.clone()))
        .route("/callback", get(page))
        .route("/config.json", get(move || async move { Json(config) }))
        .route("/static/app.js", get(|| async { web::script(APP_JS) }))
        .merge(web::shared());
    serve(router, 3000).await;
}
