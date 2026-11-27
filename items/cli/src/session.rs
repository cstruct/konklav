//! A profile's session at Konklav: signing in, keeping the tokens fresh,
//! and sending requests with DPoP proofs.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use konklav_token::ProofSigner;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::profile::Profile;
use crate::store::{ProfileLock, SecretStore, StoredSession};

/// How long before its expiry an access token is replaced.
const EXPIRY_MARGIN_SECONDS: i64 = 30;

/// Which surface a request goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// The subject-facing surface, at the profile's `url`.
    Subject,
    /// The control-plane surface, at the profile's control URL.
    Control,
}

/// One profile, with where its secrets are kept.
pub struct Context {
    pub name: String,
    pub profile: Profile,
    pub store: Arc<dyn SecretStore>,
    /// Where the profile's lock file lives; `None` for a session that no
    /// other process shares.
    pub lock_dir: Option<PathBuf>,
    http: reqwest::Client,
}

impl Context {
    /// A context for `profile`.
    ///
    /// # Errors
    ///
    /// When the HTTP client can't be built.
    pub fn new(
        name: impl Into<String>,
        profile: Profile,
        store: Arc<dyn SecretStore>,
        lock_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("konklav-cli/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::local(e.to_string()))?;
        Ok(Self {
            name: name.into(),
            profile,
            store,
            lock_dir,
            http,
        })
    }

    fn url(&self, surface: Surface, path: &str) -> Result<url::Url> {
        let base = match surface {
            Surface::Subject => &self.profile.url,
            Surface::Control => self.profile.control_base(),
        };
        if !path.starts_with('/') {
            return Err(Error::usage(format!("a path starts with /: {path:?}")));
        }
        url::Url::parse(&format!("{base}{path}"))
            .map_err(|e| Error::usage(format!("not a path: {path:?}: {e}")))
    }

    fn lock(&self) -> Result<Option<ProfileLock>> {
        self.lock_dir
            .as_deref()
            .map(|dir| ProfileLock::open(dir, &self.name))
            .transpose()
    }
}

/// A DPoP key, with the offset of Konklav's clock from ours.
struct Dpop {
    signer: ProofSigner,
    /// Seconds to add to the local clock, learned from a refused proof.
    skew: AtomicI64,
}

impl Dpop {
    fn generate() -> Self {
        loop {
            let mut secret = [0; 32];
            getrandom::fill(&mut secret).expect("the system has randomness");
            // Almost every 32 random bytes are a valid P-256 scalar.
            if let Ok(signer) = ProofSigner::from_secret_bytes(&secret) {
                return Self::new(signer);
            }
        }
    }

    fn new(signer: ProofSigner) -> Self {
        Self {
            signer,
            skew: AtomicI64::new(0),
        }
    }

    fn load(encoded: &str) -> Result<Self> {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| ProofSigner::from_secret_bytes(&bytes).ok())
            .map(Self::new)
            .ok_or_else(|| {
                Error::NotSignedIn("the stored DPoP key is unreadable; run `konklav login`".into())
            })
    }

    fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signer.secret_bytes())
    }

    fn now(&self) -> i64 {
        now() + self.skew.load(Ordering::Relaxed)
    }

    fn proof(&self, method: &Method, url: &url::Url, access_token: Option<&str>) -> String {
        let mut jti = [0; 16];
        getrandom::fill(&mut jti).expect("the system has randomness");
        self.signer.proof(
            method.as_str(),
            url.as_str(),
            access_token,
            self.now(),
            &URL_SAFE_NO_PAD.encode(jti),
        )
    }

    /// Learns Konklav's clock from a refused proof's `Date` header. Returns
    /// whether the offset changed enough to be worth a retry.
    fn learn_skew(&self, headers: &HeaderMap) -> bool {
        let Some(date) = headers
            .get(header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| chrono::DateTime::parse_from_rfc2822(v).ok())
        else {
            return false;
        };
        let skew = date.timestamp() - now();
        let changed = (skew - self.skew.load(Ordering::Relaxed)).abs() > 5;
        if changed {
            self.skew.store(skew, Ordering::Relaxed);
        }
        changed
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// An answer from Konklav.
#[derive(Debug)]
pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Response {
    /// The body as JSON, `null` when empty.
    ///
    /// # Errors
    ///
    /// When the body isn't JSON.
    pub fn json(&self) -> Result<Value> {
        if self.body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&self.body)
            .map_err(|e| Error::local(format!("Konklav answered with something not JSON: {e}")))
    }

    /// The response if it succeeded, or Konklav's error.
    ///
    /// # Errors
    ///
    /// [`Error::Api`] for a status outside 2xx.
    pub fn ok(self) -> Result<Self> {
        if self.status.is_success() {
            Ok(self)
        } else {
            Err(self.error())
        }
    }

    fn error(&self) -> Error {
        let body = serde_json::from_slice::<Value>(&self.body).unwrap_or(Value::Null);
        let field = |name: &str| body["error"][name].as_str().map(str::to_owned);
        Error::Api {
            status: self.status.as_u16(),
            code: field("code").unwrap_or_else(|| "error".into()),
            message: field("message").unwrap_or_else(|| {
                self.status
                    .canonical_reason()
                    .unwrap_or("request failed")
                    .into()
            }),
        }
    }

    fn is_proof_error(&self) -> bool {
        self.headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("invalid_dpop_proof"))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_kind: String,
    expires_in: i64,
    session_id: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// An MFA factor that can finish a login.
#[derive(Debug, Clone, Deserialize)]
pub struct Factor {
    pub id: uuid::Uuid,
    /// `totp` or `email_code`.
    pub kind: String,
}

/// What a password login comes to.
pub enum PasswordLogin {
    Done(Session),
    /// The credential needs MFA before the session is usable.
    Mfa(PendingMfa),
}

/// A partial session waiting for an MFA code.
pub struct PendingMfa {
    context: Context,
    dpop: Dpop,
    access_token: String,
    refresh_token: Option<String>,
}

impl PendingMfa {
    async fn send(&self, method: Method, path: &str, body: Option<Value>) -> Result<Response> {
        let url = self.context.url(Surface::Subject, path)?;
        let proof = self.dpop.proof(&method, &url, Some(&self.access_token));
        send(
            &self.context.http,
            method,
            url,
            Some(&self.access_token),
            &proof,
            body,
        )
        .await
    }

    /// The factors that can finish the login.
    ///
    /// # Errors
    ///
    /// When Konklav refuses or can't be reached.
    pub async fn factors(&self) -> Result<Vec<Factor>> {
        let response = self.send(Method::GET, "/v1/mfa", None).await?.ok()?;
        serde_json::from_slice(&response.body)
            .map_err(|e| Error::local(format!("unexpected factor list: {e}")))
    }

    /// Has Konklav send a code for an `email_code` factor.
    ///
    /// # Errors
    ///
    /// When Konklav refuses or can't be reached.
    pub async fn send_code(&self, factor: uuid::Uuid) -> Result<()> {
        self.send(Method::POST, &format!("/v1/mfa/{factor}/send"), None)
            .await?
            .ok()?;
        Ok(())
    }

    /// Proves `factor` with `code`. The login is done, or needs another
    /// factor.
    ///
    /// # Errors
    ///
    /// When the code is wrong, or Konklav can't be reached.
    pub async fn complete(self, factor: uuid::Uuid, code: &str) -> Result<PasswordLogin> {
        let response = self
            .send(
                Method::POST,
                "/v1/login/mfa",
                Some(json!({"factor_id": factor, "code": code})),
            )
            .await?
            .ok()?;
        let token = parse_token(&response)?;
        let refresh_token = token.refresh_token.clone().or(self.refresh_token);
        finish(self.context, self.dpop, token, refresh_token)
    }
}

fn parse_token(response: &Response) -> Result<TokenResponse> {
    serde_json::from_slice(&response.body)
        .map_err(|e| Error::local(format!("unexpected token response: {e}")))
}

/// Stores a full session, or hands back a partial one for MFA.
fn finish(
    context: Context,
    dpop: Dpop,
    token: TokenResponse,
    refresh_token: Option<String>,
) -> Result<PasswordLogin> {
    if token.token_kind == "partial" {
        return Ok(PasswordLogin::Mfa(PendingMfa {
            context,
            dpop,
            access_token: token.access_token,
            refresh_token,
        }));
    }
    let refresh_token = refresh_token
        .ok_or_else(|| Error::local("Konklav returned no refresh token for a native login"))?;
    let stored = StoredSession {
        dpop_key: dpop.encoded(),
        session_id: token.session_id,
        refresh_token,
        access_token: token.access_token,
        access_expires_at: now() + token.expires_in,
    };
    context.store.set(&context.name, &stored)?;
    Ok(PasswordLogin::Done(Session {
        context,
        dpop,
        stored,
    }))
}

/// Sends one request. A token goes under the `DPoP` scheme, always with
/// the proof made for this request.
// r[impl item.cli.dpop-every-request]
async fn send(
    http: &reqwest::Client,
    method: Method,
    url: url::Url,
    access_token: Option<&str>,
    proof: &str,
    body: Option<Value>,
) -> Result<Response> {
    let mut request = http.request(method, url).header(
        "dpop",
        HeaderValue::from_str(proof).map_err(|e| Error::local(e.to_string()))?,
    );
    if let Some(token) = access_token {
        request = request.header(header::AUTHORIZATION, format!("DPoP {token}"));
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await?;
    Ok(Response {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.bytes().await?.to_vec(),
    })
}

/// Sends a request that starts a session, retrying once if the proof was
/// refused because the clocks disagree.
async fn start(context: &Context, dpop: &Dpop, path: &str, body: Value) -> Result<Response> {
    let url = context.url(Surface::Subject, path)?;
    let mut retried = false;
    loop {
        let proof = dpop.proof(&Method::POST, &url, None);
        let response = send(
            &context.http,
            Method::POST,
            url.clone(),
            None,
            &proof,
            Some(body.clone()),
        )
        .await?;
        if !retried && response.is_proof_error() && dpop.learn_skew(&response.headers) {
            retried = true;
            continue;
        }
        return response.ok();
    }
}

/// Signs in with a password at the terminal, binding the session to a new
/// DPoP key.
///
/// # Errors
///
/// When the credentials are wrong, or Konklav can't be reached.
pub async fn login_password(
    context: Context,
    identifier: &str,
    password: &str,
) -> Result<PasswordLogin> {
    let dpop = Dpop::generate();
    let response = start(
        &context,
        &dpop,
        "/v1/login/password",
        json!({"identifier": identifier, "password": password, "client": "native"}),
    )
    .await?;
    let token = parse_token(&response)?;
    let refresh_token = token.refresh_token.clone();
    finish(context, dpop, token, refresh_token)
}

/// Signs in a service principal with its secret key, binding the session
/// to a new DPoP key.
///
/// # Errors
///
/// When the key is wrong, or Konklav can't be reached.
pub async fn login_secret_key(context: Context, key_id: &str, secret: &str) -> Result<Session> {
    let dpop = Dpop::generate();
    let response = start(
        &context,
        &dpop,
        "/v1/login/secret-key",
        json!({"key_id": key_id, "secret": secret}),
    )
    .await?;
    let token = parse_token(&response)?;
    let refresh_token = token.refresh_token.clone();
    match finish(context, dpop, token, refresh_token)? {
        PasswordLogin::Done(session) => Ok(session),
        PasswordLogin::Mfa(_) => Err(Error::local("a secret-key login never needs MFA")),
    }
}

/// A full session, bound to its DPoP key.
pub struct Session {
    context: Context,
    dpop: Dpop,
    stored: StoredSession,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("profile", &self.context.name)
            .field("session_id", &self.stored.session_id)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The profile's stored session.
    ///
    /// # Errors
    ///
    /// [`Error::NotSignedIn`] when there is none.
    pub fn load(context: Context) -> Result<Self> {
        let stored = context.store.get(&context.name)?.ok_or_else(|| {
            Error::NotSignedIn(format!(
                "not signed in to profile {:?}; run `konklav login`",
                context.name
            ))
        })?;
        let dpop = Dpop::load(&stored.dpop_key)?;
        Ok(Self {
            context,
            dpop,
            stored,
        })
    }

    /// The Konklav session id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.stored.session_id
    }

    /// The profile this session belongs to.
    #[must_use]
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Makes sure the access token is fresh, refreshing it under the
    /// profile's lock. With `force`, it refreshes even a token that looks
    /// fresh, unless another command already replaced it.
    async fn ensure_fresh(&mut self, force: bool) -> Result<()> {
        let stale_token = self.stored.access_token.clone();
        let fresh = |stored: &StoredSession| {
            stored.access_expires_at - EXPIRY_MARGIN_SECONDS > now()
                && !(force && stored.access_token == stale_token)
        };
        if fresh(&self.stored) {
            return Ok(());
        }
        let mut lock = self.context.lock()?;
        let _guard = match lock.as_mut() {
            Some(lock) => Some(lock.lock().await?),
            None => None,
        };
        // Another command may have refreshed while this one waited.
        if let Some(stored) = self.context.store.get(&self.context.name)?
            && stored.session_id == self.stored.session_id
        {
            self.stored = stored;
        }
        if fresh(&self.stored) {
            return Ok(());
        }
        self.refresh().await
    }

    async fn refresh(&mut self) -> Result<()> {
        let url = self.context.url(Surface::Subject, "/v1/refresh")?;
        let body = json!({"refresh_token": self.stored.refresh_token});
        let mut retried = false;
        let response = loop {
            let proof = self.dpop.proof(&Method::POST, &url, None);
            let response = send(
                &self.context.http,
                Method::POST,
                url.clone(),
                None,
                &proof,
                Some(body.clone()),
            )
            .await?;
            if !retried && response.is_proof_error() && self.dpop.learn_skew(&response.headers) {
                retried = true;
                continue;
            }
            break response;
        };
        if response.status == StatusCode::UNAUTHORIZED && !response.is_proof_error() {
            // The session has ended: revoked, expired, or the token reused.
            self.context.store.delete(&self.context.name)?;
            return Err(Error::NotSignedIn(format!(
                "the session for profile {:?} has ended; run `konklav login`",
                self.context.name
            )));
        }
        let token = parse_token(&response.ok()?)?;
        self.stored.access_token = token.access_token;
        self.stored.access_expires_at = now() + token.expires_in;
        if let Some(refresh) = token.refresh_token {
            self.stored.refresh_token = refresh;
        }
        self.context.store.set(&self.context.name, &self.stored)
    }

    /// Sends a request with the session's access token, refreshing it when
    /// it is stale or refused, and correcting for clock skew once.
    ///
    /// # Errors
    ///
    /// When Konklav can't be reached, or the session has ended.
    pub async fn send(
        &mut self,
        method: Method,
        surface: Surface,
        path: &str,
        body: Option<Value>,
    ) -> Result<Response> {
        let url = self.context.url(surface, path)?;
        self.ensure_fresh(false).await?;
        let (mut refreshed, mut corrected) = (false, false);
        loop {
            let proof = self
                .dpop
                .proof(&method, &url, Some(&self.stored.access_token));
            let response = send(
                &self.context.http,
                method.clone(),
                url.clone(),
                Some(&self.stored.access_token),
                &proof,
                body.clone(),
            )
            .await?;
            if response.status != StatusCode::UNAUTHORIZED {
                return Ok(response);
            }
            if response.is_proof_error() {
                if !corrected && self.dpop.learn_skew(&response.headers) {
                    corrected = true;
                    continue;
                }
                return Ok(response);
            }
            if refreshed {
                return Ok(response);
            }
            refreshed = true;
            self.ensure_fresh(true).await?;
        }
    }

    /// Signs out: revokes the session at Konklav, then deletes the local key
    /// and tokens even if that failed. Returns the revocation's error, if
    /// any, for the caller to report.
    ///
    /// # Errors
    ///
    /// When the local secrets can't be deleted.
    // r[impl item.cli.logout]
    pub async fn logout(mut self) -> Result<Option<Error>> {
        let revoked = match self
            .send(Method::POST, Surface::Subject, "/v1/sign-out", None)
            .await
        {
            Ok(response) => response.ok().err(),
            // Nothing to revoke: the session already ended.
            Err(Error::NotSignedIn(_)) => None,
            Err(e) => Some(e),
        };
        self.context.store.delete(&self.context.name)?;
        Ok(revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_key_loads_to_the_same_key() {
        let dpop = Dpop::generate();
        let again = Dpop::load(&dpop.encoded()).unwrap();
        assert_eq!(again.signer.thumbprint(), dpop.signer.thumbprint());
        assert!(Dpop::load("not a key").is_err());
    }

    #[test]
    fn skew_is_learned_from_the_date_header() {
        let dpop = Dpop::generate();
        let mut headers = HeaderMap::new();
        let ahead = chrono::Utc::now() + chrono::Duration::seconds(300);
        headers.insert(
            header::DATE,
            HeaderValue::from_str(&ahead.to_rfc2822()).unwrap(),
        );
        assert!(dpop.learn_skew(&headers));
        assert!((dpop.now() - now() - 300).abs() <= 2);
        // The same offset again is no reason to retry.
        assert!(!dpop.learn_skew(&headers));
    }
}
