//! `GET /v1/login/methods`: the interactive sign-in methods this instance
//! accepts, so a login application or relying system offers exactly those.
//! Anyone may read it, from any origin: it shows what any sign-in screen
//! shows anyway, and nothing of a provider's configuration.

use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::federation::Protocol;
use crate::{AppState, cors};

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/login/methods",
        get(methods)
            .options(cors::preflight)
            .layer(middleware::from_fn(cors::public)),
    )
}

#[derive(Debug, Serialize)]
struct Methods {
    /// `POST /v1/login/password`, which every instance accepts.
    password: bool,
    /// `POST /v1/login/passkey`, when passkeys are configured.
    passkeys: bool,
    identity_providers: Vec<IdentityProvider>,
}

#[derive(Debug, Serialize)]
struct IdentityProvider {
    id: String,
    /// What to call it, as in "Continue with GitHub".
    name: String,
    /// `oidc` or `github`.
    kind: &'static str,
    /// Where to send the browser to sign in through it, with `return_to`
    /// (one of the provider's return URLs) and optionally `dpop_jkt`.
    start_url: String,
}

/// `GET /v1/login/methods`.
// r[impl authn.login.offered]
async fn methods(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = state.auth.issuer.trim_end_matches('/');
    let identity_providers = state
        .auth
        .identity_providers
        .iter()
        .map(|provider| {
            let settings = &provider.settings;
            IdentityProvider {
                id: settings.id.clone(),
                name: settings.name.clone().unwrap_or_else(|| settings.id.clone()),
                kind: match settings.protocol {
                    Protocol::Oidc => "oidc",
                    Protocol::GitHub(_) => "github",
                },
                start_url: format!("{issuer}/v1/login/oidc/{}/start", settings.id),
            }
        })
        .collect();
    (
        // Changes only with the configuration.
        [(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        )],
        Json(Methods {
            password: true,
            passkeys: state.auth.passkeys.is_some(),
            identity_providers,
        }),
    )
}
