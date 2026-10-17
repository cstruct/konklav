mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use conclave_server::AppState;
use conclave_server::surface::{self, Surface};
use conclave_store::ConnectOptions;
use conclave_test_support::TestDatabase;
use diesel_async::RunQueryDsl;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn call(state: AppState, method: Method, uri: &str) -> (StatusCode, Value) {
    let response = surface::router(&Surface::ALL, state)
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn unreachable_pool() -> conclave_store::Pool {
    // Port 1 is reserved and never runs Postgres.
    conclave_store::connect(&ConnectOptions {
        url: "postgres://conclave:conclave@127.0.0.1:1/conclave".into(),
        max_connections: 1,
    })
    .unwrap()
}

// r[verify platform.server.health]
#[tokio::test(flavor = "multi_thread")]
async fn liveness_does_not_need_the_database() {
    let state = common::state(unreachable_pool());
    let (status, body) = call(state, Method::GET, "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"status": "ok"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn ready_when_the_database_is_migrated() {
    let db = TestDatabase::new().await;
    let state = common::state(db.pool().clone());
    let (status, body) = call(state, Method::GET, "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"status": "ready"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn not_ready_while_the_database_is_unreachable() {
    let state = common::state(unreachable_pool());
    let (status, body) = call(state, Method::GET, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "DATABASE_UNAVAILABLE");
}

#[tokio::test(flavor = "multi_thread")]
async fn not_ready_while_migrations_are_pending() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    diesel::sql_query("truncate __diesel_schema_migrations")
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);

    let state = common::state(db.pool().clone());
    let (status, body) = call(state, Method::GET, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "MIGRATIONS_PENDING");
}

// r[verify platform.error.typed-codes]
// r[verify platform.server.versioned-paths]
#[tokio::test(flavor = "multi_thread")]
async fn unknown_endpoints_get_a_typed_error() {
    let state = common::state(unreachable_pool());
    for uri in ["/v1/nope", "/nope"] {
        let (status, body) = call(state.clone(), Method::GET, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(body["error"]["code"], "NOT_FOUND", "{uri}");
        assert!(body["error"]["message"].is_string(), "{uri}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_methods_get_a_typed_error() {
    let state = common::state(unreachable_pool());
    let (status, body) = call(state, Method::POST, "/healthz").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "METHOD_NOT_ALLOWED");
}
