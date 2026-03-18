mod authz;
mod config;
mod control_plane;
mod feldera;
mod http;
mod state;
mod tenants;
mod types;

use std::io;

use actix_web::{web, App, HttpServer};
use conclave_managed_config::ManagedConfig;
use conclave_relying_auth::JwtSigner;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;
use crate::http::AppState;

// r[impl platform.server.bootstrap]
#[actix_web::main]
async fn main() -> io::Result<()> {
    initialize_tracing();

    let loaded = AppConfig::load().map_err(io::Error::other)?;
    let managed = ManagedConfig::load_from_dir(&loaded.managed_dir).map_err(io::Error::other)?;
    let signer = JwtSigner::from_seed(
        loaded.config.jwt.signing_key_id.clone(),
        loaded
            .config
            .jwt
            .signing_seed_bytes()
            .map_err(io::Error::other)?,
    );
    let verifier = signer.verifier();
    let state = AppState::from_loaded_config(loaded, managed, signer, verifier)
        .map_err(io::Error::other)?;
    let feldera_sync = state
        .sync_feldera_on_startup()
        .await
        .map_err(io::Error::other)?;
    let control_plane_bind = state.control_plane_bind_address();
    let subject_bind = state.subject_bind_address();
    let relying_bind = state.relying_bind_address();

    tracing::info!(
        control_plane_bind,
        subject_bind,
        relying_bind,
        feldera_sync = ?feldera_sync,
        "starting conclave server"
    );

    let control_plane = HttpServer::new({
        let state = state.clone();
        move || {
            App::new()
                .app_data(web::Data::new(state.clone()))
                .configure(http::configure_control_plane)
        }
    })
    .bind(&control_plane_bind)?
    .run();

    let subject = HttpServer::new({
        let state = state.clone();
        move || {
            App::new()
                .app_data(web::Data::new(state.clone()))
                .configure(http::configure_subject)
        }
    })
    .bind(&subject_bind)?
    .run();

    let relying = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(http::configure_relying)
    })
    .bind(&relying_bind)?
    .run();

    futures_util::future::try_join3(control_plane, subject, relying)
        .await
        .map(|_| ())
}

fn initialize_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}
