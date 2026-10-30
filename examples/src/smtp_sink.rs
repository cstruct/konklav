//! A minimal SMTP server that keeps every message it receives, for tests.
//! For trying the delivery worker by hand, a tool such as Mailpit shows
//! messages in a browser instead.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::{Result, fail};

/// A received message: its envelope and its raw content.
#[derive(Clone, Debug)]
pub struct Message {
    pub from: String,
    pub to: Vec<String>,
    pub data: String,
}

impl Message {
    /// The body as a mail client shows it: decoded from quoted-printable
    /// when sent that way, as long lines such as links are.
    #[must_use]
    pub fn text(&self) -> String {
        let (headers, body) = self.data.split_once("\n\n").unwrap_or(("", &self.data));
        let quoted = headers.lines().any(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-transfer-encoding: quoted-printable")
        });
        if !quoted {
            return body.to_owned();
        }
        let joined = body.replace("=\n", "");
        let mut out = Vec::new();
        let bytes = joined.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'='
                && let Some(byte) = joined
                    .get(i + 1..i + 3)
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(byte);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

/// Messages received so far, by a sink running in the background.
#[derive(Clone, Default)]
pub struct Sink {
    messages: Arc<Mutex<Vec<Message>>>,
}

impl Sink {
    /// Listens on a free local port.
    pub async fn start() -> Result<(SocketAddr, Self)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let sink = Self::default();
        let messages = sink.messages.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let messages = messages.clone();
                tokio::spawn(async move {
                    if let Err(error) = session(stream, &messages).await {
                        eprintln!("smtp sink: {error}");
                    }
                });
            }
        });
        Ok((addr, sink))
    }

    #[must_use]
    pub fn messages(&self) -> Vec<Message> {
        self.messages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Waits for a message to `recipient`.
    pub async fn wait_for(&self, recipient: &str) -> Result<Message> {
        for _ in 0..100 {
            if let Some(message) = self
                .messages()
                .into_iter()
                .rev()
                .find(|m| m.to.iter().any(|to| to.eq_ignore_ascii_case(recipient)))
            {
                return Ok(message);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(fail(format!("no message to {recipient} arrived")))
    }
}

/// The address in `MAIL FROM:<a@b>` or `RCPT TO:<a@b>`.
fn address(line: &str) -> String {
    line.split_once(':')
        .map(|(_, rest)| rest.trim().trim_start_matches('<'))
        .and_then(|rest| rest.split('>').next())
        .unwrap_or_default()
        .to_owned()
}

async fn session(stream: tokio::net::TcpStream, messages: &Mutex<Vec<Message>>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    write.write_all(b"220 konklav-example ESMTP\r\n").await?;
    let mut message = Message {
        from: String::new(),
        to: Vec::new(),
        data: String::new(),
    };
    while let Some(line) = lines.next_line().await? {
        let verb = line.get(..4).unwrap_or(&line).to_ascii_uppercase();
        let reply: &[u8] = match verb.as_str() {
            "EHLO" => b"250-konklav-example\r\n250 8BITMIME\r\n",
            "HELO" | "RSET" | "NOOP" => b"250 OK\r\n",
            "MAIL" => {
                message.from = address(&line);
                b"250 OK\r\n"
            }
            "RCPT" => {
                message.to.push(address(&line));
                b"250 OK\r\n"
            }
            "DATA" => {
                write.write_all(b"354 End with <CRLF>.<CRLF>\r\n").await?;
                let mut data = String::new();
                while let Some(line) = lines.next_line().await? {
                    if line == "." {
                        break;
                    }
                    data.push_str(line.strip_prefix('.').unwrap_or(&line));
                    data.push('\n');
                }
                message.data = data;
                messages
                    .lock()
                    .map_err(|_| fail("poisoned"))?
                    .push(std::mem::replace(
                        &mut message,
                        Message {
                            from: String::new(),
                            to: Vec::new(),
                            data: String::new(),
                        },
                    ));
                b"250 OK: queued\r\n"
            }
            "QUIT" => {
                write.write_all(b"221 Bye\r\n").await?;
                return Ok(());
            }
            _ => b"502 Command not implemented\r\n",
        };
        write.write_all(reply).await?;
    }
    Ok(())
}
