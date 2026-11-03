//! A Konklav app on an isolated database, driven through its router.

#![allow(dead_code)]

pub mod openapi;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use chrono::Duration;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use konklav_authn::PasswordHasher;
use konklav_server::feed::FeedHub;
use konklav_server::keys::ConfiguredKeys;
use konklav_server::surface::{self, Surface};
use konklav_server::{AppState, AuthContext, BrowserSettings};
use konklav_test_support::TestDatabase;
use konklav_token::{AccessClaims, JwkSet, Signer, VerifyOptions};
use serde_json::{Value, json};
use tower::ServiceExt;

pub const CONTROL_TOKEN: &str = "test-control-token-0123456789abcdef";
pub const ORIGIN: &str = "https://app.example";
pub const ISSUER: &str = "https://auth.example";
pub const AUDIENCE: &str = "api";
pub const TOTP_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

pub struct TestApp {
    pub db: TestDatabase,
    pub state: AppState,
    router: Router,
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Reply {
    pub fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or_default()
    }

    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }
}

pub fn auth_context(signer: Signer) -> AuthContext {
    AuthContext {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        access_ttl: Duration::minutes(15),
        session_lifetime: Duration::days(30),
        // Cheap parameters keep the tests fast.
        hasher: PasswordHasher::new(8, 1, 1).unwrap(),
        hashing_slots: AuthContext::default_hashing_slots(),
        signer,
        browser: Some(BrowserSettings {
            allowed_origins: vec![ORIGIN.into()],
            secure_cookies: true,
        }),
        control_token: Some(CONTROL_TOKEN.into()),
        control_token_expires_at: None,
        secrets: konklav_authn::SecretBox::new([("test", TOTP_KEY)]).unwrap(),
        // Tests that are about pacing set their own.
        pacing: konklav_server::pacing::Pacing::NONE,
        identity_providers: konklav_server::federation::Providers::default(),
        oidc: None,
        passkeys: None,
        trusted_proxies: Vec::new(),
        batches: konklav_server::batch_api::BatchLimits::DEFAULT,
    }
}

impl TestApp {
    pub async fn new() -> Self {
        Self::with_key(1).await
    }

    /// An app whose control plane has no bootstrap token.
    pub async fn without_bootstrap() -> Self {
        let app = Self::with_key(1).await;
        let mut auth = auth_context(Signer::new(SigningKey::from_bytes(&[1; 32])));
        auth.control_token = None;
        let state = AppState {
            auth: Arc::new(auth),
            ..app.state.clone()
        };
        let router = surface::router(&Surface::ALL, state.clone());
        Self {
            db: app.db,
            state,
            router,
        }
    }

    /// An app whose authentication settings `configure` adjusts.
    pub async fn with_auth(configure: impl FnOnce(&mut AuthContext)) -> Self {
        let app = Self::with_key(1).await;
        let mut auth = auth_context(Signer::new(SigningKey::from_bytes(&[1; 32])));
        configure(&mut auth);
        let state = AppState {
            auth: Arc::new(auth),
            ..app.state.clone()
        };
        let router = surface::router(&Surface::ALL, state.clone());
        Self {
            db: app.db,
            state,
            router,
        }
    }

    /// An app also served over TCP, with its address as the issuer, so other
    /// instances can federate with it. Returns the base URL.
    pub async fn serving(configure: impl FnOnce(&mut AuthContext, &str)) -> (Self, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Self::with_auth(|auth| {
            auth.issuer.clone_from(&base);
            configure(auth, &base);
        })
        .await;
        let router = app.router.clone();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (app, base)
    }

    /// An app that is also an OpenID provider.
    pub async fn with_openid_provider(provider: konklav_server::oidc::OpenIdProvider) -> Self {
        let app = Self::with_key(1).await;
        let mut auth = auth_context(Signer::new(SigningKey::from_bytes(&[1; 32])));
        auth.oidc = Some(provider);
        let state = AppState {
            auth: Arc::new(auth),
            ..app.state.clone()
        };
        let router = surface::router(&Surface::ALL, state.clone());
        Self {
            db: app.db,
            state,
            router,
        }
    }

    /// Sends an `application/x-www-form-urlencoded` body.
    pub async fn send_form(
        &self,
        uri: &str,
        headers: &[(&str, &str)],
        form: &[(&str, &str)],
    ) -> Reply {
        let body = form
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    percent_encoding::utf8_percent_encode(k, percent_encoding::NON_ALPHANUMERIC),
                    percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        // A page, such as an authorization error page, is kept as text.
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        Reply {
            status,
            headers,
            body,
        }
    }

    /// An app that signs browsers in through `providers`.
    pub async fn with_identity_providers(providers: konklav_server::federation::Providers) -> Self {
        let app = Self::with_key(1).await;
        let mut auth = auth_context(Signer::new(SigningKey::from_bytes(&[1; 32])));
        auth.identity_providers = providers;
        let state = AppState {
            auth: Arc::new(auth),
            ..app.state.clone()
        };
        let router = surface::router(&Surface::ALL, state.clone());
        Self {
            db: app.db,
            state,
            router,
        }
    }

    /// An app whose authentication endpoints are paced by `pacing`.
    pub async fn with_pacing(pacing: konklav_server::pacing::Pacing) -> Self {
        let app = Self::with_key(1).await;
        let mut auth = auth_context(Signer::new(SigningKey::from_bytes(&[1; 32])));
        auth.pacing = pacing;
        let state = AppState {
            auth: Arc::new(auth),
            ..app.state.clone()
        };
        let router = surface::router(&Surface::ALL, state.clone());
        Self {
            db: app.db,
            state,
            router,
        }
    }

    pub async fn with_key(seed: u8) -> Self {
        let db = TestDatabase::new().await;
        let keys = ConfiguredKeys {
            signer: Signer::new(SigningKey::from_bytes(&[seed; 32])),
            published: vec![SigningKey::from_bytes(&[seed; 32]).verifying_key()],
        };
        keys.sync(&mut db.pool().get().await.unwrap())
            .await
            .unwrap();
        let state = AppState {
            pool: db.pool().clone(),
            auth: Arc::new(auth_context(keys.signer)),
            feed: Arc::new(FeedHub::new(std::time::Duration::from_millis(100))),
        };
        let router = surface::router(&Surface::ALL, state.clone());
        Self { db, state, router }
    }

    pub async fn send(
        &self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> Reply {
        self.send_from(None, method, uri, headers, body).await
    }

    /// [`Self::send`] over a connection from `peer`.
    pub async fn send_from(
        &self,
        peer: Option<std::net::SocketAddr>,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> Reply {
        let mut request = Request::builder().method(method.clone()).uri(uri);
        if let Some(peer) = peer {
            request = request.extension(axum::extract::ConnectInfo(peer));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let sent = body.clone();
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        // A page, such as an authorization error page, is kept as text.
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        openapi::check(&method, uri, status, &body);
        if uri == "/v1/batch" && status.is_success() {
            openapi::check_batch(sent.as_ref(), &body);
        }
        Reply {
            status,
            headers,
            body,
        }
    }

    pub async fn control(&self, method: Method, uri: &str, body: Option<Value>) -> Reply {
        let auth = format!("Bearer {CONTROL_TOKEN}");
        self.send(method, uri, &[("authorization", &auth)], body)
            .await
    }

    pub async fn post(&self, uri: &str, body: Value) -> Reply {
        self.send(Method::POST, uri, &[], Some(body)).await
    }

    pub async fn with_bearer(&self, method: Method, uri: &str, token: &str) -> Reply {
        let auth = format!("Bearer {token}");
        self.send(method, uri, &[("authorization", &auth)], None)
            .await
    }

    /// Creates a human subject with a password and returns its id.
    pub async fn human(&self, email: &str, password: &str) -> String {
        let id = uuid::Uuid::now_v7().to_string();
        let reply = self
            .control(
                Method::PUT,
                &format!("/v1/subjects/{id}"),
                Some(json!({"kind": "human"})),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
        let reply = self
            .control(
                Method::POST,
                &format!("/v1/subjects/{id}/credentials"),
                Some(json!({"kind": "password", "identifier": email, "password": password})),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
        id
    }

    pub async fn login(&self, email: &str, password: &str) -> Reply {
        self.post(
            "/v1/login/password",
            json!({"identifier": email, "password": password}),
        )
        .await
    }

    /// Verifies an access token against the published JWKS.
    pub async fn verify(&self, token: &str) -> AccessClaims {
        let jwks: JwkSet = serde_json::from_value(
            self.send(Method::GET, "/.well-known/jwks.json", &[], None)
                .await
                .body,
        )
        .unwrap();
        let options = VerifyOptions {
            issuer: ISSUER,
            audience: AUDIENCE,
            now: chrono::Utc::now().timestamp(),
            leeway: 5,
        };
        konklav_token::verify(token, |kid| jwks.find(kid), &options).unwrap()
    }
}

/// App state over `pool`, with a fixed signing key and test settings.
pub fn state(pool: konklav_store::Pool) -> AppState {
    AppState {
        pool,
        auth: Arc::new(auth_context(Signer::new(SigningKey::from_bytes(&[1; 32])))),
        feed: Arc::new(FeedHub::new(std::time::Duration::from_millis(100))),
    }
}

impl TestApp {
    /// Creates a service principal with a secret key and returns an access
    /// token for it.
    pub async fn service_token(&self) -> String {
        let id = uuid::Uuid::now_v7();
        self.control(
            Method::PUT,
            &format!("/v1/subjects/{id}"),
            Some(json!({"kind": "service"})),
        )
        .await;
        let created = self
            .control(
                Method::POST,
                &format!("/v1/subjects/{id}/credentials"),
                Some(json!({"kind": "secret_key"})),
            )
            .await;
        let (key_id, secret) = created.body["secret_keys"]["a"]
            .as_str()
            .unwrap()
            .split_once('.')
            .unwrap();
        let login = self
            .post(
                "/v1/login/secret-key",
                json!({"key_id": key_id, "secret": secret}),
            )
            .await;
        login.body["access_token"].as_str().unwrap().to_owned()
    }
}

/// A running server on ephemeral ports, stopped on drop.
pub struct Running {
    pub subject: std::net::SocketAddr,
    pub relying: std::net::SocketAddr,
    pub control: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

impl TestApp {
    /// Serves this app's state over real sockets, waking feeds through a
    /// Postgres listener like production does.
    pub async fn serve(&self) -> Running {
        self.serve_with(konklav_server::serve::Limits::DEFAULT)
            .await
    }

    /// [`Self::serve`] with other listener limits.
    pub async fn serve_with(&self, limits: konklav_server::serve::Limits) -> Running {
        use konklav_server::config::Listen;
        use konklav_server::serve::BoundServer;
        let any = "127.0.0.1:0".parse().unwrap();
        let listen = Listen {
            subject: any,
            relying: any,
            control: any,
            trusted_proxies: Vec::new(),
        };
        let server = BoundServer::bind(&listen, self.state.clone())
            .await
            .unwrap()
            .with_limits(limits);
        let addrs = server.local_addrs().unwrap();
        let addr_of =
            |surface: Surface| addrs.iter().find(|(_, s)| s.contains(&surface)).unwrap().0;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(konklav_server::feed::listen(
            self.db.url().to_owned(),
            self.state.feed.clone(),
        ));
        tokio::spawn(server.run(async move {
            let _ = stopped.await;
        }));
        Running {
            subject: addr_of(Surface::Subject),
            relying: addr_of(Surface::Relying),
            control: addr_of(Surface::Control),
            stop: Some(stop),
        }
    }
}
