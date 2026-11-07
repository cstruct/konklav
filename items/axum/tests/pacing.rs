//! `RoutePacing`, against a fake relying host.
//!
//! The checks bound durations from below, and from above only where the
//! bound is far from the expected time, so a loaded machine can't fail them.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::Json;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use konklav_authz::{Decision, DenyReason};
use konklav_axum::{Konklav, Pacing, Policy, RoutePacing, RoutePolicy, RouterPolicy};
use support::{FakeHost, bearer, get as request, send};

const FLOOR: Duration = Duration::from_millis(200);

fn pacing() -> RoutePacing {
    RoutePacing::new(Pacing::new(FLOOR, Duration::ZERO))
}

fn policy() -> RoutePolicy {
    RouterPolicy::new(Policy::new())
        .route(&Policy::new().tenant_actions(["invite:create"]))
        .unwrap()
}

fn app(host: &Arc<FakeHost>, routes: Router) -> Router {
    routes.layer(Konklav::builder(host.clone()).build().unwrap().layer())
}

fn tenant() -> String {
    bearer("tenant")
}

async fn ok() -> &'static str {
    "ok"
}

// r[verify item.axum.route-pacing]
#[tokio::test]
async fn allows_and_denials_answer_no_sooner_than_the_floor() {
    let denying = FakeHost::deciding(|_| {
        Ok(Decision::Deny {
            reason: DenyReason::InvalidToken,
        })
    });
    for (host, status) in [
        (FakeHost::allowing(), StatusCode::OK),
        (denying, StatusCode::UNAUTHORIZED),
    ] {
        let app = app(
            &host,
            Router::new().route(
                "/invites",
                get(ok).route_layer(policy()).route_layer(pacing()),
            ),
        );
        let started = Instant::now();
        let answer = send(&app, request("/invites", &[("authorization", &tenant())])).await;
        assert_eq!(answer.status, status);
        assert!(started.elapsed() >= FLOOR, "{status}");
    }
    // Without a token, too.
    let app = app(
        &FakeHost::allowing(),
        Router::new().route(
            "/invites",
            get(ok).route_layer(policy()).route_layer(pacing()),
        ),
    );
    let started = Instant::now();
    let answer = send(&app, request("/invites", &[])).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert!(started.elapsed() >= FLOOR);
}

// r[verify item.axum.route-pacing]
#[tokio::test]
async fn slow_handlers_add_nothing_to_the_floor() {
    let slow = || async {
        tokio::time::sleep(FLOOR * 2).await;
        "ok"
    };
    let app = app(
        &FakeHost::allowing(),
        Router::new().route("/slow", get(slow).route_layer(pacing())),
    );
    let started = Instant::now();
    assert_eq!(
        send(&app, request("/slow", &[])).await.status,
        StatusCode::OK
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= FLOOR * 2);
    assert!(elapsed < FLOOR * 3, "{elapsed:?}");
}

// r[verify item.axum.route-pacing]
#[tokio::test]
async fn rejections_and_router_answers_are_paced() {
    async fn create(Json(_): Json<serde_json::Value>) -> &'static str {
        "created"
    }
    let app = app(
        &FakeHost::allowing(),
        Router::new()
            .route("/invites", post(create).route_layer(pacing()))
            .layer(pacing()),
    );
    let unparsable = Request::post("/invites")
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{"))
        .unwrap();
    for (request, status) in [
        (unparsable, StatusCode::BAD_REQUEST),
        (request("/missing", &[]), StatusCode::NOT_FOUND),
        (request("/invites", &[]), StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let started = Instant::now();
        assert_eq!(send(&app, request).await.status, status);
        assert!(started.elapsed() >= FLOOR, "{status}");
    }
}

// r[verify item.axum.route-pacing.nested]
#[tokio::test]
async fn nested_pacings_wait_for_the_longest() {
    let longer = RoutePacing::new(Pacing::new(FLOOR * 2, Duration::ZERO));
    let app = app(
        &FakeHost::allowing(),
        Router::new()
            .route("/invites", get(ok).route_layer(longer))
            .layer(pacing()),
    );
    let started = Instant::now();
    send(&app, request("/invites", &[])).await;
    let elapsed = started.elapsed();
    assert!(elapsed >= FLOOR * 2);
    assert!(elapsed < FLOOR * 3, "{elapsed:?}");
}

// r[verify item.axum.route-pacing.order]
// r[verify item.axum.misconfiguration]
#[tokio::test]
async fn pacing_inside_the_policy_is_refused() {
    let app = app(
        &FakeHost::allowing(),
        Router::new().route(
            "/invites",
            get(ok).route_layer(pacing()).route_layer(policy()),
        ),
    );
    let answer = send(&app, request("/invites", &[("authorization", &tenant())])).await;
    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        answer.body,
        serde_json::json!({"error": {"code": "route_policy_error"}})
    );
}

// r[verify item.axum.route-pacing]
#[tokio::test]
async fn websocket_upgrades_are_not_paced() {
    let slow = RoutePacing::new(Pacing::new(Duration::from_secs(30), Duration::ZERO));
    let app = app(
        &FakeHost::allowing(),
        Router::new().route("/feed", get(ok).route_layer(slow)),
    );
    let started = Instant::now();
    send(
        &app,
        request(
            "/feed",
            &[("connection", "upgrade"), ("upgrade", "websocket")],
        ),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(10));
}
