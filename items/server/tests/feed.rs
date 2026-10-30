mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::TestApp;
use futures_util::StreamExt;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

#[derive(Debug)]
struct SseEvent {
    id: Option<String>,
    event: String,
    data: Value,
}

/// Reads Server-Sent Events from a response, skipping comments.
struct SseReader {
    stream: futures_util::stream::BoxStream<'static, reqwest::Result<bytes_like::Bytes>>,
    buffer: String,
}

mod bytes_like {
    pub type Bytes = axum::body::Bytes;
}

impl SseReader {
    async fn open(url: &str, token: &str, last_event_id: Option<&str>) -> Self {
        let mut request = reqwest::Client::new().get(url).bearer_auth(token);
        if let Some(id) = last_event_id {
            request = request.header("last-event-id", id);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 200);
        Self {
            stream: response.bytes_stream().boxed(),
            buffer: String::new(),
        }
    }

    async fn next(&mut self) -> SseEvent {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(end) = self.buffer.find("\n\n") {
                    let block: String = self.buffer.drain(..end + 2).collect();
                    let mut event = SseEvent {
                        id: None,
                        event: "message".into(),
                        data: Value::Null,
                    };
                    let mut data = String::new();
                    for line in block.lines() {
                        if let Some(v) = line.strip_prefix("id:") {
                            event.id = Some(v.trim().to_owned());
                        } else if let Some(v) = line.strip_prefix("event:") {
                            v.trim().clone_into(&mut event.event);
                        } else if let Some(v) = line.strip_prefix("data:") {
                            data.push_str(v.trim());
                        }
                    }
                    if data.is_empty() {
                        continue; // a heartbeat comment
                    }
                    event.data = serde_json::from_str(&data).unwrap();
                    return event;
                }
                let chunk = self.stream.next().await.expect("stream ended").unwrap();
                self.buffer.push_str(&String::from_utf8_lossy(&chunk));
            }
        })
        .await
        .expect("no event within 10s")
    }
}

async fn login(app: &TestApp, email: &str) -> Value {
    app.login(email, PASSWORD).await.body
}

// r[verify feed.sse]
// r[verify feed.notify-hint-only]
#[tokio::test(flavor = "multi_thread")]
async fn streams_events_as_they_happen_and_resumes_by_cursor() {
    let app = TestApp::new().await;
    let running = app.serve().await;
    let service = app.service_token().await;
    let email = "ada@example.com";
    app.human(email, PASSWORD).await;
    let url = format!("http://{}/v1/events?kinds=session.changed", running.relying);

    let mut feed = SseReader::open(&url, &service, None).await;
    let first = login(&app, email).await;
    let event = feed.next().await;
    assert_eq!(event.event, "session.changed");
    assert_eq!(event.data["payload"]["session"], first["session_id"]);
    assert_eq!(event.data["payload"]["version"], 1);
    let resume_from = event.id.clone().unwrap();
    assert_eq!(event.data["cursor"].to_string(), resume_from);
    drop(feed);

    // Events written while disconnected arrive after resuming.
    let second = login(&app, email).await;
    let mut feed = SseReader::open(&url, &service, Some(&resume_from)).await;
    let event = feed.next().await;
    assert_eq!(event.data["payload"]["session"], second["session_id"]);
}

// r[verify feed.sse.kinds-filter]
#[tokio::test(flavor = "multi_thread")]
async fn filters_by_kind() {
    let app = TestApp::new().await;
    let running = app.serve().await;
    let service = app.service_token().await;
    let url = format!("http://{}/v1/events?kinds=tenant.changed", running.relying);
    let mut feed = SseReader::open(&url, &service, None).await;
    app.human("ada@example.com", PASSWORD).await;
    login(&app, "ada@example.com").await; // session.changed, filtered out
    let tenant = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        Some(json!({})),
    )
    .await;
    let event = feed.next().await;
    assert_eq!(event.event, "tenant.changed");
    assert_eq!(event.data["payload"]["tenant"], tenant.to_string());
}

// r[verify feed.reset]
// r[verify feed.retention]
#[tokio::test(flavor = "multi_thread")]
async fn resuming_from_a_pruned_cursor_starts_with_a_reset() {
    let app = TestApp::new().await;
    let running = app.serve().await;
    let service = app.service_token().await;
    app.human("ada@example.com", PASSWORD).await;
    login(&app, "ada@example.com").await;
    {
        let mut conn = app.db.pool().get().await.unwrap();
        let pruned = konklav_store::events::prune_before(
            &mut conn,
            chrono::Utc::now() + chrono::Duration::seconds(1),
            1000,
        )
        .await
        .unwrap();
        assert!(pruned > 1);
        let watermark = konklav_store::events::pruned_through(&mut conn)
            .await
            .unwrap();
        assert!(watermark.get() > 1);
    }
    let url = format!("http://{}/v1/events", running.relying);
    let mut feed = SseReader::open(&url, &service, Some("1")).await;
    let event = feed.next().await;
    assert_eq!(event.event, "reset");

    // A cursor from the future resets too.
    let mut feed = SseReader::open(&url, &service, Some("999999")).await;
    assert_eq!(feed.next().await.event, "reset");
}

// r[verify feed.batch]
// r[verify feed.at-least-once]
#[tokio::test(flavor = "multi_thread")]
async fn serves_pages_of_events() {
    let app = TestApp::new().await;
    let service = app.service_token().await;
    app.human("ada@example.com", PASSWORD).await;
    for _ in 0..3 {
        login(&app, "ada@example.com").await;
    }
    let first = app
        .with_bearer(
            Method::GET,
            "/v1/events/batch?after=0&limit=2&kinds=session.changed",
            &service,
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    assert_eq!(first.body["reset"], false);
    let next = first.body["next"].as_i64().unwrap();
    let rest = app
        .with_bearer(
            Method::GET,
            &format!("/v1/events/batch?after={next}&kinds=session.changed"),
            &service,
        )
        .await;
    let total = first.body["events"].as_array().unwrap().len()
        + rest.body["events"].as_array().unwrap().len();
    assert_eq!(
        total, 4,
        "one session for the service principal, three for ada"
    );
    // Re-reading from the same cursor yields the same events again.
    let again = app
        .with_bearer(
            Method::GET,
            &format!("/v1/events/batch?after={next}&kinds=session.changed"),
            &service,
        )
        .await;
    assert_eq!(again.body["events"], rest.body["events"]);
}

// r[verify feed.authorization]
#[tokio::test(flavor = "multi_thread")]
async fn only_service_principals_read_the_feed() {
    let app = TestApp::new().await;
    app.human("ada@example.com", PASSWORD).await;
    let human = login(&app, "ada@example.com").await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let reply = app
        .with_bearer(Method::GET, "/v1/events/batch", &human)
        .await;
    assert_eq!(reply.code(), "FORBIDDEN");
}

// r[verify feed.self-contained-session]
#[tokio::test(flavor = "multi_thread")]
async fn session_states_match_session_changed_payloads() {
    let app = TestApp::new().await;
    let service = app.service_token().await;
    app.human("ada@example.com", PASSWORD).await;
    let session = login(&app, "ada@example.com").await;
    let id = session["session_id"].as_str().unwrap();
    let state = app
        .with_bearer(Method::GET, &format!("/v1/session-states/{id}"), &service)
        .await;
    assert_eq!(state.body["session"], id);
    assert_eq!(state.body["version"], 1);
    assert_eq!(state.body["revoked"], false);
    assert!(state.body["expires_at"].is_i64());
}

// r[verify platform.server.limits]
#[tokio::test(flavor = "multi_thread")]
async fn change_feed_streams_are_capped() {
    use konklav_server::feed::FeedHub;
    use konklav_server::surface::{self, Surface};
    use tower::ServiceExt;

    let app = TestApp::new().await;
    let token = app.service_token().await;
    let state = konklav_server::AppState {
        feed: std::sync::Arc::new(FeedHub::new(Duration::from_millis(100)).with_max_streams(1)),
        ..app.state.clone()
    };
    let router = surface::router(&Surface::ALL, state);
    let open = || {
        let request = axum::http::Request::get("/v1/events")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        router.clone().oneshot(request)
    };
    let first = open().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = open().await.unwrap();
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(first);
    let third = open().await.unwrap();
    assert_eq!(
        third.status(),
        StatusCode::OK,
        "closing a stream frees its slot"
    );
}
