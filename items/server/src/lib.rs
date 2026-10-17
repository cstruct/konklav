//! The Conclave server: one binary serving the subject-facing, relying and
//! control-plane surfaces.

pub mod config;
pub mod error;
pub mod health;
pub mod serve;
pub mod surface;

use conclave_store::Pool;

/// State shared by every handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
}
