//! The app's backend, on <http://localhost:3001>: a relying system.
//!
//! Every request must carry `Authorization: DPoP <token>` and a fresh
//! `DPoP` proof signed by the key the token is bound to. The relying client
//! checks both, verifies the token offline against Konklav's keys, and
//! decides from entitlements it keeps fresh from Konklav's change feed, so
//! a role the admin page removes, or a session it ends, stops working here
//! within about a second.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use konklav_authz::{Decision, DenyReason, Requirements};
use konklav_relying_client::{Presented, RelyingClient, RequestDescriptor};
use konklav_sso_example::{claims_of, env, relying_client, secrets, serve};
use konklav_token::TokenKind;
use serde::{Deserialize, Serialize};
use serde_json::json;

const ACTIONS: [&str; 2] = ["notes:read", "notes:write"];

#[derive(Clone, Serialize)]
struct Note {
    text: String,
    author: String,
    at: u128,
}

struct App {
    konklav: RelyingClient,
    public_url: String,
    notes: Mutex<VecDeque<Note>>,
}

/// A refusal, answered as JSON with a `WWW-Authenticate` challenge on 401.
struct Refused {
    status: StatusCode,
    message: String,
    challenge: Option<&'static str>,
}

impl Refused {
    fn unauthorized(message: &str, challenge: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
            challenge: Some(challenge),
        }
    }

    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            challenge: None,
        }
    }
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(json!({"message": self.message}))).into_response();
        if let Some(challenge) = self.challenge {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        response
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Allows the request if its token holds `action`, or refuses it. The
/// relying client gets the raw headers and the URL the browser addressed:
/// the proof's `htu` names this public URL, not the container's.
async fn decide(
    app: &App,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    action: &str,
) -> Result<(), Refused> {
    let header = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let Some(authorization) = header(header::AUTHORIZATION) else {
        return Err(Refused::unauthorized(
            "sign in first",
            "DPoP algs=\"ES256\"",
        ));
    };
    let presented = Presented {
        authorization,
        dpop: header(HeaderName::from_static("dpop")),
        request: Some(RequestDescriptor {
            method: method.to_string(),
            url: format!("{}{path}", app.public_url),
        }),
    };
    let requirements = Requirements {
        global: BTreeSet::from([action.to_owned()]),
        token_kinds: Some(BTreeSet::from([TokenKind::Identity])),
        ..Requirements::default()
    };
    // An error means Konklav couldn't be reached and the caches can't be
    // trusted: deny.
    let decision = app
        .konklav
        .decide_request(&presented, &requirements)
        .await
        .map_err(|_| {
            Refused::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization is unavailable; try again",
            )
        })?;
    match decision {
        Decision::Allow { .. } => Ok(()),
        Decision::Deny {
            reason: DenyReason::InvalidDpopProof,
        } => Err(Refused::unauthorized(
            "the DPoP proof is missing, invalid or replayed",
            "DPoP error=\"invalid_dpop_proof\"",
        )),
        Decision::Deny {
            reason: DenyReason::InvalidToken,
        } => Err(Refused::unauthorized(
            "the token is invalid or its session has ended",
            "DPoP error=\"invalid_token\"",
        )),
        _ => Err(Refused::new(
            StatusCode::FORBIDDEN,
            format!("your roles don't grant {action}"),
        )),
    }
}

/// Whether the caller holds one of the app's actions. One per request,
/// since a proof is accepted only once.
async fn can(
    State(app): State<Arc<App>>,
    Path(action): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, Refused> {
    if !ACTIONS.contains(&action.as_str()) {
        return Err(Refused::new(
            StatusCode::NOT_FOUND,
            format!("no action {action}"),
        ));
    }
    let allowed = match decide(
        &app,
        &method,
        &format!("/api/can/{action}"),
        &headers,
        &action,
    )
    .await
    {
        Ok(()) => true,
        Err(refused) if refused.status == StatusCode::FORBIDDEN => false,
        Err(refused) => return Err(refused),
    };
    Ok(Json(json!({"action": action, "allowed": allowed})).into_response())
}

async fn list_notes(
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, Refused> {
    decide(&app, &method, "/api/notes", &headers, "notes:read").await?;
    let notes: Vec<Note> = app
        .notes
        .lock()
        .expect("notes")
        .iter()
        .rev()
        .cloned()
        .collect();
    Ok(Json(json!({"notes": notes})).into_response())
}

#[derive(Deserialize)]
struct NewNote {
    text: String,
}

async fn add_note(
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    Json(note): Json<NewNote>,
) -> Result<Response, Refused> {
    decide(&app, &method, "/api/notes", &headers, "notes:write").await?;
    // The relying client verified the token above; read who it names.
    let subject = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .and_then(|(_, token)| claims_of(token))
        .and_then(|claims| claims["sub"].as_str().map(str::to_owned))
        .unwrap_or_default();
    let text: String = note.text.trim().chars().take(200).collect();
    if text.is_empty() {
        return Err(Refused::new(StatusCode::BAD_REQUEST, "a note needs text"));
    }
    let mut notes = app.notes.lock().expect("notes");
    if notes.len() == 50 {
        notes.pop_front();
    }
    notes.push_back(Note {
        text,
        author: subject.chars().take(8).collect(),
        at: now_ms(),
    });
    Ok((StatusCode::CREATED, Json(json!({"ok": true}))).into_response())
}

/// CORS for the frontend's origin only, with the `Authorization` and `DPoP`
/// headers and no cookies: the token and proof are the only credentials.
async fn cors(State(origin): State<HeaderValue>, request: Request, next: Next) -> Response {
    let allowed = request.headers().get(header::ORIGIN) == Some(&origin);
    let mut response = if request.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };
    if allowed {
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, dpop, content-type"),
        );
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("www-authenticate"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("origin"));
    }
    response
}

#[tokio::main]
async fn main() {
    let app = Arc::new(App {
        // The `app` OIDC client's tokens carry this audience.
        konklav: relying_client("app-api", &secrets().app_api_key).await,
        public_url: env("PUBLIC_URL"),
        notes: Mutex::new(VecDeque::from([Note {
            text: "Welcome! Editors can add notes.".into(),
            author: "the example".into(),
            at: now_ms(),
        }])),
    });
    let origin = HeaderValue::from_str(&env("FRONTEND_ORIGIN")).expect("an origin");
    let router = Router::new()
        .route("/api/can/{action}", get(can))
        .route("/api/notes", get(list_notes).post(add_note))
        .with_state(app)
        .layer(middleware::from_fn_with_state(origin, cors));
    serve(router, 3001).await;
}
