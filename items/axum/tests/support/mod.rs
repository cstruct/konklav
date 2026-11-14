//! A relying host that records what it is asked, and helpers to send
//! requests through a router.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use konklav_authz::{Decision, Requirements};
use konklav_axum::{Accepted, BoxFuture, RelyingHost};
use konklav_relying_client::{Error, Presented, Verified};
use konklav_token::AccessClaims;
use serde_json::{Value, json};
use tower::ServiceExt;

pub const TENANT: &str = "01900000-0000-7000-8000-000000000001";
pub const OTHER_TENANT: &str = "01900000-0000-7000-8000-000000000002";
pub const SUBJECT: &str = "01900000-0000-7000-8000-0000000000aa";

/// The claims of a token of `kind`, in `TENANT` unless it is no tenant
/// token.
pub fn claims(kind: &str) -> AccessClaims {
    let mut claims = json!({
        "iss": "https://auth.example",
        "aud": "api",
        "sub": SUBJECT,
        "jti": "j-1",
        "iat": 0,
        "exp": i64::MAX,
        "knd": kind,
        "sid": "01900000-0000-7000-8000-0000000000bb",
        "sv": 1,
        "amr": ["pwd"],
        "auth_time": 0,
    });
    if kind == "tenant" {
        claims["tid"] = json!(TENANT);
    }
    serde_json::from_value(claims).unwrap()
}

type Decide = dyn Fn(&Requirements) -> Result<Decision, Error> + Send + Sync;

/// Stands in for a started `RelyingClient`. It accepts the tokens `tenant`
/// and `identity` (with claims of that kind), refuses `invalid`, refuses
/// the proof of `bad-proof`, fails for `unreachable`, and decides with
/// `decide`.
pub struct FakeHost {
    decide: Box<Decide>,
    pub accepted: Mutex<Vec<Presented>>,
    pub decided: Mutex<Vec<Requirements>>,
    /// Whether each decision was marked as the route decision.
    pub routes: Mutex<Vec<bool>>,
    pub verified: Mutex<Vec<Presented>>,
    /// How many presentations were released.
    pub released: Mutex<usize>,
}

impl FakeHost {
    pub fn allowing() -> Arc<Self> {
        Self::deciding(|_| Ok(Decision::allow()))
    }

    pub fn deciding(
        decide: impl Fn(&Requirements) -> Result<Decision, Error> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            decide: Box::new(decide),
            accepted: Mutex::default(),
            decided: Mutex::default(),
            routes: Mutex::default(),
            verified: Mutex::default(),
            released: Mutex::default(),
        })
    }

    fn token(presented: &Presented) -> Result<Verified<AccessClaims>, Error> {
        match presented.access_token().unwrap_or_default() {
            "tenant" => Ok(Verified::Valid(claims("tenant"))),
            "identity" => Ok(Verified::Valid(claims("identity"))),
            "bad-proof" => Ok(Verified::InvalidProof),
            "unreachable" => Err(Error::Exhausted),
            _ => Ok(Verified::Invalid),
        }
    }

    pub fn accepted(&self) -> Vec<Presented> {
        self.accepted.lock().unwrap().clone()
    }

    pub fn decided(&self) -> Vec<Requirements> {
        self.decided.lock().unwrap().clone()
    }

    pub fn routes(&self) -> Vec<bool> {
        self.routes.lock().unwrap().clone()
    }

    pub fn verified(&self) -> Vec<Presented> {
        self.verified.lock().unwrap().clone()
    }

    pub fn released(&self) -> usize {
        *self.released.lock().unwrap()
    }
}

impl RelyingHost for FakeHost {
    fn accept_request<'a>(
        &'a self,
        presented: &'a Presented,
    ) -> BoxFuture<'a, Result<Verified<Accepted>, Error>> {
        Box::pin(async move {
            self.accepted.lock().unwrap().push(presented.clone());
            Ok(match Self::token(presented)? {
                Verified::Valid(claims) => Verified::Valid(Accepted::new(claims, ())),
                Verified::Invalid => Verified::Invalid,
                Verified::InvalidProof => Verified::InvalidProof,
            })
        })
    }

    fn decide_accepted<'a>(
        &'a self,
        _: &'a Accepted,
        requirements: &'a Requirements,
        route: bool,
    ) -> BoxFuture<'a, Result<Decision, Error>> {
        Box::pin(async move {
            self.decided.lock().unwrap().push(requirements.clone());
            self.routes.lock().unwrap().push(route);
            (self.decide)(requirements)
        })
    }

    fn verify_request<'a>(
        &'a self,
        presented: &'a Presented,
    ) -> BoxFuture<'a, Result<Verified<AccessClaims>, Error>> {
        Box::pin(async move {
            self.verified.lock().unwrap().push(presented.clone());
            Self::token(presented)
        })
    }

    fn release_accepted(&self, _: &Accepted) {
        *self.released.lock().unwrap() += 1;
    }
}

/// An answer, read.
pub struct Answer {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub body: Value,
}

impl Answer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|value| value.to_str().unwrap())
    }
}

/// A GET of `uri` from 203.0.113.9, with `headers`.
pub fn get(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut request = Request::get(uri).header("host", "api.example");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request.body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 4000))));
    request
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

pub async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response: Response<Body> = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    Answer {
        status,
        headers,
        body,
    }
}

/// The path parameters of a request, as a handler can answer them.
pub fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}
