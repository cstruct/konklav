//! Runs the `smtp_delivery` scenario; see `konklav_examples::scenario::smtp_delivery`.
//! Needs the development Postgres (`mise run db:up`) and a built
//! `konklav-server` (`mise run example smtp-delivery` builds it).

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let binary = konklav_examples::harness::server_binary();
    match konklav_examples::scenario::smtp_delivery::run(&binary).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("failed: {error}");
            ExitCode::FAILURE
        }
    }
}
