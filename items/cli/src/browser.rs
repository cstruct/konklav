//! Signing in through the browser: the native login hand-off.
//!
//! The CLI listens on a loopback port, opens Konklav's
//! `/v1/login-requests/native/authorize` in the browser with a PKCE
//! challenge and its DPoP key's thumbprint, and waits for the login
//! application to send the browser back with a code. It exchanges the code,
//! with the verifier and a proof from that key, for a bound session.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::session::{self, Context, Session, Surface};

/// The name the CLI gives Konklav, which the login application shows when
/// it asks to confirm.
pub const APP: &str = "konklav-cli";

/// How long a sign-in may take in the browser.
pub const TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The largest request head the listener reads.
const MAX_HEAD: usize = 8 * 1024;

const AUTHORIZE: &str = "/v1/login-requests/native/authorize";
const TOKEN: &str = "/v1/login-requests/native/token";

/// A browser sign-in in progress, listening for its callback.
pub struct BrowserLogin {
    context: Context,
    dpop: session::Dpop,
    listener: TcpListener,
    redirect_uri: String,
    state: String,
    verifier: String,
    url: url::Url,
}

fn random() -> String {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).expect("the system has randomness");
    URL_SAFE_NO_PAD.encode(bytes)
}

impl BrowserLogin {
    /// Starts listening and works out the URL to open.
    ///
    /// # Errors
    ///
    /// A usage error when this Konklav doesn't offer browser sign-in; or
    /// when it can't be reached, or no loopback port is free.
    // r[impl item.cli.loopback]
    pub async fn start(context: Context) -> Result<Self> {
        let authorize = context.url(Surface::Subject, AUTHORIZE)?;
        // Without parameters, the endpoint refuses the request (400) if the
        // hand-off is on, and doesn't know it (404) if it's off; either way
        // nothing is started.
        let probe = context.http().get(authorize.clone()).send().await?;
        if probe.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::usage(
                "this Konklav doesn't offer browser sign-in (its native_handoff isn't \
                 configured); use --password or --secret-key",
            ));
        }
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| Error::local(format!("can't listen on a loopback port: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| Error::local(e.to_string()))?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{port}/callback");
        let dpop = session::Dpop::generate();
        let state = random();
        let verifier = random();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut url = authorize;
        url.query_pairs_mut()
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("dpop_jkt", &dpop.thumbprint())
            .append_pair("state", &state)
            .append_pair("app", APP);
        Ok(Self {
            context,
            dpop,
            listener,
            redirect_uri,
            state,
            verifier,
            url,
        })
    }

    /// The URL to open in the browser.
    #[must_use]
    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    /// Waits up to `timeout` for the browser to come back, then exchanges
    /// the code for a session and stores it.
    ///
    /// # Errors
    ///
    /// When the sign-in is refused, times out, or the exchange fails.
    pub async fn finish(self, timeout: Duration) -> Result<Session> {
        let issuer = self.context.profile.url.clone();
        let code =
            tokio::time::timeout(timeout, next_callback(&self.listener, &self.state, &issuer))
                .await
                .map_err(|_| {
                    Error::local(format!(
                        "no sign-in within {} minutes; run `konklav login` again",
                        timeout.as_secs() / 60
                    ))
                })??;
        // The listener stops here: one callback only.
        drop(self.listener);
        let response = session::start(
            &self.context,
            &self.dpop,
            TOKEN,
            serde_json::json!({
                "code": code,
                "code_verifier": self.verifier,
                "redirect_uri": self.redirect_uri,
            }),
        )
        .await?;
        session::from_response(self.context, self.dpop, &response)
    }
}

/// What came back to the callback.
#[derive(Debug, PartialEq, Eq)]
enum Callback {
    Code(String),
    Refused(String),
    /// Not this sign-in's callback: another path, or another `state`.
    Other(u16),
}

/// Reads callbacks until one with this sign-in's `state` arrives, and
/// answers each with a page for the browser.
async fn next_callback(listener: &TcpListener, state: &str, issuer: &str) -> Result<String> {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(Ok(target)) =
            tokio::time::timeout(Duration::from_secs(10), request_target(&mut stream)).await
        else {
            continue;
        };
        match parse_callback(&target, state, issuer) {
            Callback::Code(code) => {
                respond(
                    &mut stream,
                    200,
                    "Signed in",
                    "The Konklav CLI is signed in. You can close this tab.",
                )
                .await;
                return Ok(code);
            }
            Callback::Refused(error) => {
                respond(
                    &mut stream,
                    200,
                    "Sign-in cancelled",
                    "The Konklav CLI wasn't signed in. You can close this tab.",
                )
                .await;
                return Err(Error::local(format!("the sign-in was refused ({error})")));
            }
            Callback::Other(status) => {
                respond(
                    &mut stream,
                    status,
                    "Not this sign-in",
                    "This isn't the sign-in the Konklav CLI is waiting for.",
                )
                .await;
            }
        }
    }
}

/// The target of an HTTP request's first line.
async fn request_target(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut buffer = [0; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await?;
        if read == 0 || head.len() + read > MAX_HEAD {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        head.extend_from_slice(&buffer[..read]);
    }
    let text = String::from_utf8_lossy(&head);
    let line = text.lines().next().unwrap_or_default();
    match line.split(' ').collect::<Vec<_>>().as_slice() {
        ["GET", target, version] if version.starts_with("HTTP/1.") => Ok((*target).to_owned()),
        _ => Err(std::io::ErrorKind::InvalidData.into()),
    }
}

fn parse_callback(target: &str, state: &str, issuer: &str) -> Callback {
    let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return Callback::Other(400);
    };
    if url.path() != "/callback" {
        return Callback::Other(404);
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if param("state").as_deref() != Some(state) {
        return Callback::Other(400);
    }
    // RFC 9207: the answer must come from the Konklav this sign-in went to.
    if param("iss").is_some_and(|iss| iss.trim_end_matches('/') != issuer) {
        return Callback::Refused("it came from another issuer".into());
    }
    match (param("code"), param("error")) {
        (Some(code), None) => Callback::Code(code),
        (_, Some(error)) => Callback::Refused(error),
        (None, None) => Callback::Other(400),
    }
}

async fn respond(stream: &mut TcpStream, status: u16, title: &str, text: &str) {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let page = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><title>{title}</title>\
         <body style=\"font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto\">\
         <h1>{title}</h1><p>{text}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\n\
         content-length: {}\r\ncache-control: no-store\r\nreferrer-policy: no-referrer\r\n\
         connection: close\r\n\r\n{page}",
        page.len()
    );
    stream.write_all(response.as_bytes()).await.ok();
    stream.shutdown().await.ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://id.example";

    #[test]
    fn only_this_sign_ins_callback_counts() {
        assert_eq!(
            parse_callback(
                "/callback?code=c&state=s&iss=https%3A%2F%2Fid.example",
                "s",
                ISSUER
            ),
            Callback::Code("c".into())
        );
        assert_eq!(
            parse_callback("/callback?code=c&state=s", "s", ISSUER),
            Callback::Code("c".into())
        );
        assert_eq!(
            parse_callback("/callback?error=access_denied&state=s", "s", ISSUER),
            Callback::Refused("access_denied".into())
        );
        assert_eq!(
            parse_callback("/callback?code=c&state=other", "s", ISSUER),
            Callback::Other(400)
        );
        assert_eq!(
            parse_callback("/callback?code=c", "s", ISSUER),
            Callback::Other(400)
        );
        assert_eq!(
            parse_callback("/favicon.ico", "s", ISSUER),
            Callback::Other(404)
        );
        assert!(matches!(
            parse_callback(
                "/callback?code=c&state=s&iss=https%3A%2F%2Fevil.example",
                "s",
                ISSUER
            ),
            Callback::Refused(_)
        ));
    }

    // r[verify item.cli.loopback]
    #[tokio::test]
    async fn the_listener_waits_for_the_matching_state_and_answers_the_browser() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let waiting = tokio::spawn(async move { next_callback(&listener, "s", ISSUER).await });
        let get = |target: &'static str| async move {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream
                .write_all(format!("GET {target} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).await.unwrap();
            answer
        };
        assert!(get("/favicon.ico").await.starts_with("HTTP/1.1 404"));
        assert!(
            get("/callback?code=x&state=wrong")
                .await
                .starts_with("HTTP/1.1 400")
        );
        assert!(
            get("/callback?code=x&state=s")
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert_eq!(waiting.await.unwrap().unwrap(), "x");
    }
}
