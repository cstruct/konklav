//! A reference delivery worker: follows Konklav's change feed as a service
//! principal holding `konklav.delivery`, and sends each email delivery
//! request over SMTP.
//!
//! Konklav never sends messages itself; it emits `delivery.requested`
//! events with the one-time code or link token to send. This worker is the
//! smallest piece that turns those into email. Copy it, or run it with
//! `cargo run -p konklav-examples --bin delivery-worker`.

use std::time::Duration;

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::Value;

use crate::{Result, fail};

/// How the worker talks to the SMTP server.
#[derive(Clone, Debug)]
pub enum Tls {
    /// Plain text, for a local server.
    None,
    /// Upgraded with `STARTTLS`, conventionally on port 587.
    StartTls,
    /// TLS from the start, conventionally on port 465.
    Implicit,
}

#[derive(Clone, Debug)]
pub struct Smtp {
    pub host: String,
    pub port: u16,
    pub tls: Tls,
    pub credentials: Option<(String, String)>,
}

/// What the worker needs.
#[derive(Clone, Debug)]
pub struct Worker {
    /// Konklav's subject-facing base URL, for signing in.
    pub subject: String,
    /// Konklav's relying base URL, for the feed.
    pub relying: String,
    /// The service principal's secret key, as `key_id.secret`.
    pub key: String,
    pub smtp: Smtp,
    /// The `From` address.
    pub from: String,
    /// The app's base URL for links, such as `https://app.example`. Links
    /// go to `{link_base}/{purpose}?token=...`, a page of the app that
    /// completes the flow with Konklav.
    pub link_base: String,
}

/// Where the worker is in the feed, and its current access token.
pub struct Follower {
    worker: Worker,
    http: reqwest::Client,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    token: Option<String>,
    /// The cursor of the last event handled.
    pub cursor: i64,
}

impl Follower {
    /// Starts after `cursor`; 0 reads the feed from its start. Requests
    /// whose challenge has expired carry no material and are skipped, so
    /// starting early only re-reads.
    pub fn new(worker: Worker, cursor: i64) -> Result<Self> {
        let smtp = &worker.smtp;
        let mut builder = match smtp.tls {
            Tls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host),
            Tls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)?,
            Tls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)?,
        }
        .port(smtp.port);
        if let Some((user, password)) = &smtp.credentials {
            builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
        }
        Ok(Self {
            mailer: builder.build(),
            http: reqwest::Client::new(),
            worker,
            token: None,
            cursor,
        })
    }

    async fn sign_in(&mut self) -> Result<String> {
        let (key_id, secret) = self
            .worker
            .key
            .split_once('.')
            .ok_or_else(|| fail("the secret key must be `key_id.secret`"))?;
        let reply: Value = self
            .http
            .post(format!("{}/v1/login/secret-key", self.worker.subject))
            .json(&serde_json::json!({"key_id": key_id, "secret": secret}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let token = reply["access_token"]
            .as_str()
            .ok_or_else(|| fail(format!("no access token in {reply}")))?
            .to_owned();
        self.token = Some(token.clone());
        Ok(token)
    }

    /// The next page of delivery requests, signing in again when the access
    /// token has expired.
    async fn page(&mut self) -> Result<Value> {
        for _ in 0..2 {
            let token = match self.token.clone() {
                Some(token) => token,
                None => self.sign_in().await?,
            };
            let reply = self
                .http
                .get(format!("{}/v1/events/batch", self.worker.relying))
                .query(&[
                    ("after", self.cursor.to_string()),
                    ("kinds", "delivery.requested".into()),
                    ("limit", "100".into()),
                ])
                .bearer_auth(token)
                .send()
                .await?;
            if reply.status() == reqwest::StatusCode::UNAUTHORIZED {
                self.token = None;
                continue;
            }
            return Ok(reply.error_for_status()?.json().await?);
        }
        Err(fail("Konklav refused the service principal"))
    }

    /// Sends what has been requested since the cursor. Returns how many
    /// messages went out.
    pub async fn deliver_pending(&mut self) -> Result<usize> {
        let page = self.page().await?;
        let mut sent = 0;
        for event in page["events"].as_array().into_iter().flatten() {
            if let Some(message) = self.compose(&event["payload"])? {
                self.mailer.send(message).await?;
                sent += 1;
            }
            if let Some(cursor) = event["cursor"].as_i64() {
                self.cursor = cursor;
            }
        }
        if let Some(next) = page["next"].as_i64() {
            self.cursor = self.cursor.max(next);
        }
        Ok(sent)
    }

    /// Delivers forever, polling every second when there's nothing new.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            match self.deliver_pending().await {
                Ok(0) => tokio::time::sleep(Duration::from_secs(1)).await,
                Ok(_) => {}
                Err(error) => {
                    eprintln!("delivery failed, retrying: {error}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// The email for a delivery request, or `None` for one this worker
    /// doesn't send: another channel, or one whose challenge expired.
    fn compose(&self, request: &Value) -> Result<Option<Message>> {
        let material = &request["material"];
        if request["channel"] != "email" || material.is_null() {
            return Ok(None);
        }
        let purpose = request["purpose"].as_str().unwrap_or_default();
        let link = |page: &str| {
            format!(
                "{}/{page}?token={}",
                self.worker.link_base.trim_end_matches('/'),
                material["token"].as_str().unwrap_or_default()
            )
        };
        let (subject, body) = match purpose {
            "email_link" => (
                "Your sign-in link",
                format!("Open this link to sign in:\n\n{}\n", link("email-link")),
            ),
            "reset_password" => (
                "Reset your password",
                format!(
                    "Open this link to choose a new password:\n\n{}\n",
                    link("reset-password")
                ),
            ),
            "invite" => (
                "You're invited",
                format!(
                    "Open this link to accept the invitation:\n\n{}\n",
                    link("invite")
                ),
            ),
            "mfa_email_code" => (
                "Your sign-in code",
                format!(
                    "Your code is {}\n",
                    material["code"].as_str().unwrap_or_default()
                ),
            ),
            other => return Err(fail(format!("unknown delivery purpose `{other}`"))),
        };
        let to = request["recipient"].as_str().unwrap_or_default();
        Ok(Some(
            Message::builder()
                .from(self.worker.from.parse()?)
                .to(to.parse()?)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body)?,
        ))
    }
}
