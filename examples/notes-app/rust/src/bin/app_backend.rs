//! The app's backend, on <http://localhost:3001>: a relying system.
//!
//! Every request must carry `Authorization: DPoP <token>` and a fresh
//! `DPoP` proof signed by the key the token is bound to. `konklav-axum`
//! evaluates each route's policy through the relying client, which checks
//! both, verifies the token offline against Konklav's keys, and decides
//! from entitlements it keeps fresh from Konklav's change feed. A role the
//! admin page removes, or a session it ends, stops working here within
//! about a second.
//!
//! Each note remembers the subject who wrote it. When Konklav erases a
//! subject, the relying client says so and the backend deletes that
//! person's notes.
//!
//! Adding notes is rate limited per person, through Valkey, and in memory
//! while Valkey is unavailable.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use konklav_authz::{Decision, DenyReason, Requirements};
use konklav_axum::{
    Denied, Forbidden, IdentityToken, Konklav, Policy, RoutePolicy, RouteRateLimit, RouterPolicy,
    Scheme, Unauthenticated,
};
use konklav_core::SubjectId;
use konklav_relying_client::rate_limit::{
    RateLimit, RateLimitConfig, RateLimitWindow, StoreSecret,
};
use konklav_relying_client::{ErasureNotice, Presented, RelyingClient, RequestDescriptor};
use konklav_sso_example::{env, relying_client, secrets, serve};
use konklav_token::TokenKind;
use serde::{Deserialize, Serialize};
use serde_json::json;

const ACTIONS: [&str; 2] = ["notes:read", "notes:write"];

#[derive(Clone, Serialize)]
struct Note {
    text: String,
    author: String,
    at: u128,
    /// Who wrote the note, so it can be deleted when Konklav erases them.
    #[serde(skip)]
    subject: Option<SubjectId>,
}

struct App {
    konklav: RelyingClient,
    public_url: String,
    notes: Mutex<VecDeque<Note>>,
}

fn message(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({"message": message.into()}))).into_response()
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Answers refusals as the app's page reads errors, with a `message`, and
/// keeps the default answer's status and headers: the `WWW-Authenticate`
/// challenge, and `Retry-After` on a 429.
fn denied(denied: Denied) -> Response {
    let text = match &denied {
        Denied::Unauthenticated { reason, .. } => match reason {
            Unauthenticated::MissingToken => "sign in first",
            Unauthenticated::InvalidDpopProof => "the DPoP proof is missing, invalid or replayed",
            Unauthenticated::InvalidToken => "the token is invalid or its session has ended",
        }
        .to_owned(),
        Denied::Forbidden(Forbidden::Decision(DenyReason::MissingActions { actions })) => {
            let actions: Vec<_> = actions.iter().map(String::as_str).collect();
            format!("your roles don't grant {}", actions.join(", "))
        }
        Denied::Unavailable => "authorization is unavailable; try again".to_owned(),
        Denied::RateLimited { .. } => "too many requests".to_owned(),
        other => other.code().to_owned(),
    };
    let mut response = denied.into_response();
    *response.body_mut() = axum::body::Body::from(json!({"message": text}).to_string());
    response
}

/// Whether the caller holds one of the app's actions. The action comes from
/// the path, so no route policy can name it: the route is public and
/// decides itself. One per request, since a proof is accepted only once.
async fn can(
    State(app): State<Arc<App>>,
    Path(action): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if !ACTIONS.contains(&action.as_str()) {
        return message(StatusCode::NOT_FOUND, format!("no action {action}"));
    }
    let header = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let Some(authorization) = header(header::AUTHORIZATION) else {
        return denied(Denied::Unauthenticated {
            reason: Unauthenticated::MissingToken,
            scheme: None,
        });
    };
    let presented = Presented {
        authorization,
        dpop: header(HeaderName::from_static("dpop")),
        // The URL the browser addressed: the proof's `htu` names this
        // public URL, not the container's.
        request: Some(RequestDescriptor {
            method: method.to_string(),
            url: format!("{}/api/can/{action}", app.public_url),
        }),
    };
    let requirements = Requirements {
        global: BTreeSet::from([action.clone()]),
        token_kinds: Some(BTreeSet::from([TokenKind::Identity])),
        ..Requirements::default()
    };
    // An error means Konklav couldn't be reached and the caches can't be
    // trusted: deny.
    let Ok(decision) = app.konklav.decide_request(&presented, &requirements).await else {
        return denied(Denied::Unavailable);
    };
    let unauthenticated = |reason| {
        denied(Denied::Unauthenticated {
            reason,
            scheme: Some(Scheme::DPoP),
        })
    };
    match decision {
        Decision::Deny {
            reason: DenyReason::InvalidDpopProof,
        } => unauthenticated(Unauthenticated::InvalidDpopProof),
        Decision::Deny {
            reason: DenyReason::InvalidToken,
        } => unauthenticated(Unauthenticated::InvalidToken),
        decision => Json(json!({
            "action": action,
            "allowed": matches!(decision, Decision::Allow { .. }),
        }))
        .into_response(),
    }
}

async fn list_notes(State(app): State<Arc<App>>) -> Response {
    let notes: Vec<Note> = app
        .notes
        .lock()
        .expect("notes")
        .iter()
        .rev()
        .cloned()
        .collect();
    Json(json!({"notes": notes})).into_response()
}

#[derive(Deserialize)]
struct NewNote {
    text: String,
}

// `token` is the token the relying core verified for this request.
async fn add_note(
    State(app): State<Arc<App>>,
    token: IdentityToken,
    Json(note): Json<NewNote>,
) -> Response {
    let text: String = note.text.trim().chars().take(200).collect();
    if text.is_empty() {
        return message(StatusCode::BAD_REQUEST, "a note needs text");
    }
    let mut notes = app.notes.lock().expect("notes");
    if notes.len() == 50 {
        notes.pop_front();
    }
    notes.push_back(Note {
        text,
        author: token.sub.to_string().chars().take(8).collect(),
        at: now_ms(),
        subject: Some(token.sub),
    });
    (StatusCode::CREATED, Json(json!({"ok": true}))).into_response()
}

/// Removes what this relying system holds about erased subjects: their
/// notes. The notes live in memory, so a restart has none to catch up on;
/// a relying system with a database would also keep the time it has handled
/// erasures up to and read `erased_subjects` from there when it starts, as
/// the Python version does.
async fn forget_erased(app: Arc<App>) {
    let mut erasures = app.konklav.erasures();
    while let Some(notice) = erasures.recv().await {
        let erased = match notice {
            ErasureNotice::Erased(erased) => vec![erased],
            // The feed couldn't resume where this client left off, so some
            // erasures may never arrive on it: read them from Konklav.
            ErasureNotice::Missed { since } => match app.konklav.erased_subjects(since).await {
                Ok(erased) => erased,
                Err(error) => {
                    eprintln!("could not read the erased subjects: {error}");
                    continue;
                }
            },
        };
        let mut notes = app.notes.lock().expect("notes");
        notes.retain(|note| !erased.iter().any(|e| note.subject == Some(e.subject)));
    }
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
        // `Retry-After` isn't a CORS-safelisted header, so the page can read
        // it on a 429 only when it is exposed.
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("www-authenticate, retry-after"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("origin"));
    }
    response
}

/// Five notes at once, then one every 12 seconds, per person, shared
/// through Valkey and counted in memory while Valkey is unavailable.
async fn note_writes(rate_limit_secret: &str) -> RateLimit {
    // Valkey, through the redis client library: it speaks the same protocol.
    let valkey = redis::Client::open(env("REDIS_URL"))
        .expect("a redis:// URL")
        .get_connection_manager()
        .await
        .expect("reaching Valkey");
    RateLimit::with_redis(
        RateLimitConfig::new(
            "notes-app.note-writes",
            vec![RateLimitWindow {
                size: 5,
                period_ms: 60_000,
            }],
        ),
        valkey,
        // Keys are hashed under this before they reach Valkey. The setup
        // service generated it.
        StoreSecret::new(rate_limit_secret.as_bytes()).expect("a 32-byte secret"),
        RateLimit::DEFAULT_TIMEOUT,
    )
    .expect("a valid rate limit")
}

#[tokio::main]
async fn main() {
    let secrets = secrets();
    let public_url = env("PUBLIC_URL");
    // The `app` OIDC client's tokens carry this audience.
    let client = relying_client("app-api", &secrets.app_api_key).await;
    let konklav = Konklav::builder(client.clone())
        .public_url({
            let public_url = public_url.clone();
            move |parts: &Parts| format!("{public_url}{}", parts.uri.path())
        })
        .respond_with(denied)
        .build()
        .expect("a valid configuration");
    let app = Arc::new(App {
        konklav: client,
        public_url,
        notes: Mutex::new(VecDeque::from([Note {
            text: "Welcome! Editors can add notes.".into(),
            author: "the example".into(),
            at: now_ms(),
            subject: None,
        }])),
    });

    tokio::spawn(forget_erased(app.clone()));

    // The app's sign-in gives identity tokens: it selects no tenant.
    let notes_api = RouterPolicy::new(Policy::new().token_kinds([TokenKind::Identity]));
    let read = notes_api
        .route(&Policy::new().global_actions(["notes:read"]))
        .expect("a valid policy");
    // Counts only the requests the policy allows, keyed by the verified
    // token's subject. A refusal is 429 with `Retry-After`.
    let per_person =
        RouteRateLimit::new(note_writes(&secrets.rate_limit_secret).await, "{token:sub}")
            .expect("a valid key template");
    let write = notes_api
        .route(&Policy::new().global_actions(["notes:write"]))
        .and_then(|policy| policy.rate_limit(per_person))
        .expect("a valid policy");

    let origin = HeaderValue::from_str(&env("FRONTEND_ORIGIN")).expect("an origin");
    let router = Router::new()
        // For compose's healthcheck: answers once the app has started.
        .route(
            "/healthz",
            get(|| async { "ok" }).route_layer(RoutePolicy::public()),
        )
        .route(
            "/api/can/{action}",
            get(can).route_layer(RoutePolicy::public()),
        )
        .route(
            "/api/notes",
            get(list_notes)
                .route_layer(read)
                .merge(axum::routing::post(add_note).route_layer(write)),
        )
        .with_state(app)
        .layer(konklav.layer())
        .layer(middleware::from_fn_with_state(origin, cors));
    serve(router, 3001).await;
}
