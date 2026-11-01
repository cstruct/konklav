//! Email-link sign-in, delivered by the reference worker over SMTP.
//!
//! 1. Konklav starts, and an operator creates a person who signs in with
//!    email links, and a service principal holding `konklav.delivery`.
//! 2. The delivery worker follows the feed and sends to an SMTP server.
//! 3. The person asks for a link; the app takes the token from the link in
//!    the email and completes the sign-in.

use std::path::Path;

use serde_json::json;

use crate::delivery::{Follower, Smtp, Tls, Worker};
use crate::harness::{Server, Setup};
use crate::smtp_sink::Sink;
use crate::{Result, check, fail, step};

const EMAIL: &str = "ada@example.com";
const APP: &str = "https://app.example";

/// Runs the scenario against a server started from `binary`.
pub async fn run(binary: &Path) -> Result<()> {
    step("starting Konklav");
    let konklav = Server::start(&Setup {
        binary: Some(binary.to_owned()),
        ..Setup::default()
    })
    .await?;
    konklav
        .human(json!({"kind": "email_link", "identifier": EMAIL}))
        .await?;
    let key = konklav.service_principal(&["konklav.delivery"]).await?;

    step("starting an SMTP server and the delivery worker");
    let (smtp, sink) = Sink::start().await?;
    let mut worker = Follower::new(
        Worker {
            subject: konklav.subject.clone(),
            relying: konklav.relying.clone(),
            key,
            smtp: Smtp {
                host: smtp.ip().to_string(),
                port: smtp.port(),
                tls: Tls::None,
                credentials: None,
            },
            from: "Konklav <no-reply@example.com>".into(),
            link_base: APP.into(),
        },
        0,
    )?;
    let worker = tokio::spawn(async move { worker.run().await });

    step(&format!("{EMAIL} asks for a sign-in link"));
    let (status, _) = konklav
        .post("/v1/login/email-link/start", &json!({"email": EMAIL}))
        .await?;
    check(status == reqwest::StatusCode::ACCEPTED, || {
        format!("starting an email link: {status}")
    })?;

    let message = sink.wait_for(EMAIL).await?;
    let text = message.text();
    println!("    the worker sent:\n{}", indent(&text));
    let prefix = format!("{APP}/email-link?token=");
    let token = text
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .ok_or_else(|| fail("the email has no sign-in link"))?;

    step("the app completes the sign-in with the link's token");
    let (status, body) = konklav
        .post("/v1/login/email-link/complete", &json!({"token": token}))
        .await?;
    check(status.is_success(), || {
        format!("completing: {status} {body}")
    })?;
    check(body["access_token"].is_string(), || {
        format!("no access token in {body}")
    })?;
    step("signed in");

    let (status, _) = konklav
        .post("/v1/login/email-link/complete", &json!({"token": token}))
        .await?;
    check(status == reqwest::StatusCode::UNAUTHORIZED, || {
        format!("a second use of the link was answered {status}")
    })?;
    step("the link doesn't work twice");
    worker.abort();
    Ok(())
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("      {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}
