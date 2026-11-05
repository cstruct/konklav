//! Runs the `dpop` scenario; see `konklav_examples::scenario::dpop`.
//! Needs the development Postgres (`mise run db:up`) and a built
//! `konklav-server` (`mise run example dpop` builds it).

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let binary = konklav_examples::harness::server_binary();
    match konklav_examples::scenario::dpop::run(&binary).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("failed: {error}");
            ExitCode::FAILURE
        }
    }
}
