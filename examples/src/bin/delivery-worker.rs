//! The reference delivery worker, against any Konklav: sends its email
//! delivery requests over SMTP. Configured from the environment:
//!
//! - `KONKLAV_SUBJECT_URL` and `KONKLAV_RELYING_URL`: Konklav's surfaces
//! - `KONKLAV_DELIVERY_KEY`: a secret key (`key_id.secret`) of a service
//!   principal holding the `konklav.delivery` global role
//! - `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_TLS` (`starttls`, `implicit` or
//!   `none`), and optionally `SMTP_USERNAME` and `SMTP_PASSWORD`
//! - `MAIL_FROM`, such as `Example <no-reply@example.com>`
//! - `LINK_BASE`: the app's base URL that links in emails go to
//! - `KONKLAV_DELIVERY_AFTER` (0): the feed cursor to start after
//!
//! It keeps its cursor in memory, so a restart reads the feed again from
//! `KONKLAV_DELIVERY_AFTER`; requests whose challenge has expired are
//! skipped, but live ones are sent again.

use std::process::ExitCode;

use konklav_examples::delivery::{Follower, Smtp, Tls, Worker};
use konklav_examples::{Result, fail};

fn var(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| fail(format!("{name} is not set")))
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn worker() -> Result<(Worker, i64)> {
    let tls = match optional("SMTP_TLS").as_deref() {
        None | Some("starttls") => Tls::StartTls,
        Some("implicit") => Tls::Implicit,
        Some("none") => Tls::None,
        Some(other) => {
            return Err(fail(format!(
                "SMTP_TLS `{other}` is not starttls, implicit or none"
            )));
        }
    };
    let port = match optional("SMTP_PORT") {
        Some(port) => port.parse()?,
        None => 587,
    };
    let credentials = match (optional("SMTP_USERNAME"), optional("SMTP_PASSWORD")) {
        (Some(user), Some(password)) => Some((user, password)),
        _ => None,
    };
    let after = match optional("KONKLAV_DELIVERY_AFTER") {
        Some(after) => after.parse()?,
        None => 0,
    };
    Ok((
        Worker {
            subject: var("KONKLAV_SUBJECT_URL")?,
            relying: var("KONKLAV_RELYING_URL")?,
            key: var("KONKLAV_DELIVERY_KEY")?,
            smtp: Smtp {
                host: var("SMTP_HOST")?,
                port,
                tls,
                credentials,
            },
            from: var("MAIL_FROM")?,
            link_base: var("LINK_BASE")?,
        },
        after,
    ))
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = async {
        let (worker, after) = worker()?;
        Follower::new(worker, after)?.run().await
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
