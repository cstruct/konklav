//! A reference delivery worker: follows Konklav's change feed as a service
//! principal holding `konklav.delivery`, and sends each email delivery
//! request over SMTP.
//!
//! Konklav never sends messages itself; it emits `delivery.requested`
//! events with the one-time code or link token to send. This worker is the
//! smallest piece that turns those into email. Copy it, or run it with
//! `cargo run -p konklav-examples --bin delivery-worker`.

use std::time::Duration;

use lettre::message::Mailbox;
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
    from: Mailbox,
    token: Option<String>,
    /// The cursor of the last event handled.
    pub cursor: i64,
}

impl Follower {
    /// Starts after `cursor`; 0 reads the feed from its start. Requests
    /// whose challenge has expired carry no material and are skipped, so
    /// starting early only re-reads.
    pub fn new(worker: Worker, cursor: i64) -> Result<Self> {
        // Checked here, so a bad `From` stops the worker as it starts
        // instead of failing every message.
        let from = worker
            .from
            .parse()
            .map_err(|error| fail(format!("the From address: {error}")))?;
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
            from,
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
    ///
    /// A request that can never be sent (a recipient that is no address or
    /// that the SMTP server refuses, a purpose this worker doesn't know) is
    /// logged and skipped, so it can't hold up the requests after it. Any
    /// other failure is returned with the cursor just before the request
    /// it happened on, and the next call tries that request again.
    pub async fn deliver_pending(&mut self) -> Result<usize> {
        let page = self.page().await?;
        let mut sent = 0;
        for event in page["events"].as_array().into_iter().flatten() {
            let skipped = match self.compose(&event["payload"]) {
                Ok(None) => None,
                Ok(Some(message)) => match self.mailer.send(message).await {
                    Ok(_) => {
                        sent += 1;
                        None
                    }
                    Err(error) if refuses_the_message(&error) => Some(error.into()),
                    Err(error) => return Err(error.into()),
                },
                Err(error) => Some(error),
            };
            if let Some(error) = skipped {
                // Not the recipient or the material: logs outlive both.
                eprintln!(
                    "skipping the delivery request at cursor {}: {error}",
                    event["cursor"]
                );
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
    /// doesn't send: another channel, or one whose challenge expired. An
    /// error is about this request alone, and trying again won't help.
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
                .from(self.from.clone())
                .to(to.parse()?)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body)?,
        ))
    }
}

/// Whether the SMTP server refused this one message for good, as it does
/// a mailbox it doesn't have. A refused sign-in (530, 534, 535, 538) is
/// permanent to SMTP too, but it is the worker's to fix and every message
/// would get it, so it is retried like a failure to connect.
fn refuses_the_message(error: &lettre::transport::smtp::Error) -> bool {
    let sign_in = matches!(error.status().map(u16::from), Some(530 | 534 | 535 | 538));
    error.is_permanent() && !sign_in
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::{Query, State};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;

    use super::*;
    use crate::smtp_sink::{BUSY, NO_MAILBOX, Sink};

    /// A delivery request for an email link, at `cursor`.
    fn request(cursor: i64, recipient: &str, purpose: &str) -> Value {
        json!({"cursor": cursor, "kind": "delivery.requested", "payload": {
            "channel": "email", "purpose": purpose, "recipient": recipient,
            "material": {"token": format!("token-{cursor}")},
        }})
    }

    /// A worker following a feed that holds `events`, and the SMTP server
    /// it sends to.
    async fn follower(events: Vec<Value>) -> (Follower, Sink) {
        async fn batch(
            State(events): State<Arc<Vec<Value>>>,
            Query(query): Query<std::collections::HashMap<String, String>>,
        ) -> Json<Value> {
            let after: i64 = query["after"].parse().unwrap();
            let events: Vec<&Value> = events
                .iter()
                .filter(|event| event["cursor"].as_i64() > Some(after))
                .collect();
            Json(json!({"events": events}))
        }
        let konklav = Router::new()
            .route(
                "/v1/login/secret-key",
                post(|| async { Json(json!({"access_token": "token"})) }),
            )
            .route("/v1/events/batch", get(batch))
            .with_state(Arc::new(events));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, konklav).await });
        let (smtp, sink) = Sink::start().await.unwrap();
        let worker = Worker {
            subject: url.clone(),
            relying: url,
            key: "key.secret".into(),
            smtp: Smtp {
                host: smtp.ip().to_string(),
                port: smtp.port(),
                tls: Tls::None,
                credentials: None,
            },
            from: "Konklav <no-reply@example.com>".into(),
            link_base: "https://app.example".into(),
        };
        (Follower::new(worker, 0).unwrap(), sink)
    }

    #[tokio::test]
    async fn a_request_that_cannot_be_sent_does_not_hold_up_the_rest() {
        let (mut follower, sink) = follower(vec![
            request(1, "not an address", "email_link"),
            request(2, "ada@example.com", "a_purpose_from_the_future"),
            request(3, &format!("gone{NO_MAILBOX}"), "email_link"),
            request(4, "grace@example.com", "email_link"),
        ])
        .await;
        assert_eq!(follower.deliver_pending().await.unwrap(), 1);
        assert_eq!(follower.cursor, 4);
        let sent = sink.messages();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, ["grace@example.com"]);
        assert!(sent[0].text().contains("token-4"));
    }

    #[tokio::test]
    async fn a_failure_that_may_pass_is_tried_again() {
        let (mut follower, sink) = follower(vec![
            request(1, "ada@example.com", "email_link"),
            request(2, &format!("grace{BUSY}"), "email_link"),
            request(3, "edsger@example.com", "email_link"),
        ])
        .await;
        // Stops at the request the server put off, and stays there.
        for _ in 0..2 {
            follower.deliver_pending().await.unwrap_err();
            assert_eq!(follower.cursor, 1);
        }
        assert_eq!(sink.messages().len(), 1);
    }

    #[test]
    fn a_from_that_is_no_address_stops_the_worker_as_it_starts() {
        let worker = Worker {
            subject: String::new(),
            relying: String::new(),
            key: String::new(),
            smtp: Smtp {
                host: "localhost".into(),
                port: 25,
                tls: Tls::None,
                credentials: None,
            },
            from: "nobody".into(),
            link_base: String::new(),
        };
        assert!(Follower::new(worker, 0).is_err());
    }
}
