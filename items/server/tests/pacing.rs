mod common;

use std::time::{Duration, Instant};

use axum::http::{Method, StatusCode};
use common::TestApp;
use konklav_server::pacing::Pacing;
use serde_json::json;

const PACING: Pacing = Pacing {
    floor: Duration::from_millis(300),
    jitter: Duration::from_millis(50),
};

async fn timed<T>(request: impl Future<Output = T>) -> (T, Duration) {
    let started = Instant::now();
    let reply = request.await;
    (reply, started.elapsed())
}

// r[verify authn.pacing]
#[tokio::test(flavor = "multi_thread")]
async fn authentication_endpoints_wait_out_the_floor_whether_or_not_identifiers_exist() {
    let app = TestApp::with_pacing(PACING).await;
    app.human("known@example.com", "correct horse battery")
        .await;
    let least = Duration::from_millis(250);
    let most = Duration::from_millis(600);

    for (uri, body) in [
        (
            "/v1/login/password",
            json!({"identifier": "known@example.com", "password": "correct horse battery"}),
        ),
        (
            "/v1/login/password",
            json!({"identifier": "unknown@example.com", "password": "correct horse battery"}),
        ),
        (
            "/v1/login/email-link/start",
            json!({"email": "known@example.com"}),
        ),
        (
            "/v1/password-reset/start",
            json!({"identifier": "unknown@example.com"}),
        ),
    ] {
        let (reply, took) = timed(app.post(uri, body)).await;
        assert!(
            (least..most).contains(&took),
            "{uri} took {took:?}, answering {:?}",
            reply.status
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn other_endpoints_are_not_paced() {
    let app = TestApp::with_pacing(PACING).await;
    let (reply, took) = timed(app.send(Method::GET, "/healthz", &[], None)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(took < Duration::from_millis(250), "took {took:?}");
    let (reply, took) = timed(app.post("/v1/refresh", json!({"refresh_token": "x.y"}))).await;
    assert_ne!(reply.status, StatusCode::OK);
    assert!(took < Duration::from_millis(250), "took {took:?}");
}
