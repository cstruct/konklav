//! Starts Konklav for the OpenID conformance suite and writes the test plan
//! configuration, then serves until interrupted. See
//! `konklav_examples::conformance` and `examples/README.md`.
//!
//! - `CONFORMANCE_HOST` (`host.docker.internal`): how the suite reaches this
//!   machine
//! - `CONFORMANCE_ISSUER`: the issuer, when a proxy terminates TLS in front
//!   of Konklav; it prints the port to proxy to
//! - `CONFORMANCE_SUITE` (`https://localhost.emobix.co.uk:8443`): the suite
//! - `CONFORMANCE_ALIAS` (`konklav`): the alias in its callback URLs
//! - `CONFORMANCE_CONFIG` (`conformance.json`): where to write the config

use std::process::ExitCode;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = async {
        let ready = konklav_examples::conformance::start(
            &konklav_examples::harness::server_binary(),
            &env("CONFORMANCE_HOST", "host.docker.internal"),
            std::env::var("CONFORMANCE_ISSUER").ok(),
            &env("CONFORMANCE_SUITE", "https://localhost.emobix.co.uk:8443"),
            &env("CONFORMANCE_ALIAS", "konklav"),
        )
        .await?;
        let path = env("CONFORMANCE_CONFIG", "conformance.json");
        std::fs::write(&path, serde_json::to_string_pretty(&ready.config)?)?;
        println!("issuer {}", ready.konklav.issuer);
        println!("subject-facing surface {}", ready.konklav.subject);
        println!("wrote {path}; serving until interrupted");
        tokio::signal::ctrl_c().await?;
        Ok::<_, konklav_examples::Error>(())
    }
    .await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
