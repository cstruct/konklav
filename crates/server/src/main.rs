mod authz;
mod config;
mod control_plane;
mod feldera;
mod http;
mod tenants;
mod types;

use std::io;

use actix_web::{web, App, HttpServer};
use conclave_managed_config::ManagedConfig;
use tracing_subscriber::EnvFilter;

use crate::authz::compile_managed_authz;
use crate::config::AppConfig;
use crate::http::AppState;
use crate::tenants::compile_managed_tenants;

// r[impl platform.server.bootstrap]
#[actix_web::main]
async fn main() -> io::Result<()> {
    initialize_tracing();

    let loaded = AppConfig::load().map_err(io::Error::other)?;
    let managed = ManagedConfig::load_from_dir(&loaded.managed_dir).map_err(io::Error::other)?;
    let authz = compile_managed_authz(&managed.managed).map_err(io::Error::other)?;
    let tenants = compile_managed_tenants(&managed.managed, &authz).map_err(io::Error::other)?;
    let state = AppState::from_loaded_config(loaded, managed, authz, tenants);
    let bind_address = state.bind_address();

    tracing::info!(bind_address, "starting conclave server");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(http::configure)
    })
    .bind(&bind_address)?
    .run()
    .await
}

fn initialize_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}
