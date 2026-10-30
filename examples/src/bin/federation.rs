//! Runs the `federation` scenario; see `konklav_examples::scenario::federation`.
//! Needs the development Postgres (`mise run db:up`) and a built
//! `konklav-server` (`mise run example federation` builds it).

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let binary = konklav_examples::harness::server_binary();
    match konklav_examples::scenario::federation::run(&binary).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("failed: {error}");
            ExitCode::FAILURE
        }
    }
}
