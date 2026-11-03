//! Starts a server on a fresh database for another language's tests, such
//! as the Python control-plane client's. Prints one JSON line with the
//! surfaces' URLs, the issuer and audience of its tokens and the bootstrap
//! token, then serves until
//! stdin closes, when it stops the server and drops the database.
//!
//! Needs the development Postgres (`mise run db:up`) and a built
//! `konklav-server`.

use std::process::ExitCode;

use konklav_examples::harness::{AUDIENCE, Server, Setup};
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> ExitCode {
    let server = match Server::start(&Setup::default()).await {
        Ok(server) => server,
        Err(error) => {
            eprintln!("failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let ready = serde_json::json!({
        "subject": server.subject,
        "relying": server.relying,
        "control": server.control,
        "issuer": server.issuer,
        "audience": AUDIENCE,
        "bootstrap_token": server.bootstrap_token,
    });
    println!("{ready}");
    let mut rest = Vec::new();
    let _ = tokio::io::stdin().read_to_end(&mut rest).await;
    drop(server);
    ExitCode::SUCCESS
}
