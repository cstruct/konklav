//! Batches: several control-plane operations in one request, applied all
//! or nothing (`platform.batch.*`).

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{CONTROL_TOKEN, TestApp};
use diesel::QueryableByName;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

async fn batch(app: &TestApp, operations: Value) -> common::Reply {
    app.control(
        Method::POST,
        "/v1/batch",
        Some(json!({"operations": operations})),
    )
    .await
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

async fn count(app: &TestApp, query: &str) -> i64 {
    let mut conn = app.db.pool().get().await.unwrap();
    diesel::sql_query(query)
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

async fn reader_role(app: &TestApp, tenant: &str) {
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "document:read"}]})),
    )
    .await;
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}/roles/reader"),
            Some(json!({"policies": [{"action": "document:read", "effect": "allow"}]})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
}

/// Creating a person with a password, a membership and a role, naming
/// earlier creates by the ids chosen for them.
fn onboarding(subject: &str, tenant: &str, email: &str) -> Value {
    let membership = new_id();
    json!([
        {"method": "PUT", "path": format!("/subjects/{subject}"), "body": {"kind": "human"}},
        {"method": "POST", "path": format!("/subjects/{subject}/credentials"),
         "body": {"id": new_id(), "kind": "password", "identifier": email, "password": PASSWORD}},
        {"method": "PUT", "path": format!("/memberships/{membership}"),
         "body": {"subject": subject, "tenant": tenant}},
        {"method": "POST", "path": format!("/memberships/{membership}/assignments"),
         "body": {"id": new_id(), "role": "reader"}},
    ])
}

// r[verify platform.batch.atomic]
// r[verify platform.batch.results]
// r[verify platform.batch.same-as-alone]
#[tokio::test(flavor = "multi_thread")]
async fn later_operations_use_what_earlier_ones_created() {
    let app = TestApp::new().await;
    let tenant = new_id();
    reader_role(&app, &tenant).await;
    let subject = new_id();
    let reply = batch(&app, onboarding(&subject, &tenant, "ada@example.com")).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);

    let results = reply.body["results"].as_array().unwrap();
    let statuses: Vec<_> = results
        .iter()
        .map(|r| r["status"].as_u64().unwrap())
        .collect();
    assert_eq!(statuses, [201, 201, 201, 201]);
    assert_eq!(results[0]["body"]["id"], subject.as_str());
    let last = results[3]["body"]["cursor"].as_i64().unwrap();
    assert_eq!(
        reply.body["cursor"].as_i64(),
        Some(last),
        "the batch's last event"
    );

    assert_eq!(
        app.login("ada@example.com", PASSWORD).await.status,
        StatusCode::OK
    );
    let entitlements = app
        .control(
            Method::GET,
            &format!("/v1/subjects/{subject}/entitlements?tenant={tenant}"),
            None,
        )
        .await;
    assert!(
        entitlements.body["tenant"]
            .as_array()
            .unwrap()
            .contains(&json!("document:read")),
        "{:?}",
        entitlements.body
    );
}

// r[verify platform.batch.atomic]
// r[verify platform.batch.failure]
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_operation_leaves_no_trace() {
    let app = TestApp::new().await;
    let tenant = new_id();
    reader_role(&app, &tenant).await;
    let events = count(&app, "select count(*) as count from event").await;

    let subject = new_id();
    let mut operations = onboarding(&subject, &tenant, "ada@example.com");
    operations.as_array_mut().unwrap().push(json!(
        {"method": "POST", "path": format!("/subjects/{subject}/global-assignments"),
         "body": {"role": "no-such-role"}}
    ));
    let reply = batch(&app, operations).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{:?}", reply.body);
    assert_eq!(reply.code(), "NOT_FOUND");
    assert_eq!(reply.body["error"]["operation"], 4);

    let gone = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    assert_eq!(gone.code(), "NOT_FOUND");
    assert_eq!(
        app.login("ada@example.com", PASSWORD).await.code(),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        count(&app, "select count(*) as count from event").await,
        events,
        "no events"
    );

    // An unknown path fails like it would alone.
    let reply = batch(
        &app,
        json!([
            {"method": "PUT", "path": format!("/subjects/{subject}"), "body": {"kind": "human"}},
            {"method": "POST", "path": "/no/such/thing"},
        ]),
    )
    .await;
    assert_eq!(reply.code(), "NOT_FOUND");
    assert_eq!(reply.body["error"]["operation"], 1);
    assert_eq!(
        app.control(Method::GET, &format!("/v1/subjects/{subject}"), None)
            .await
            .code(),
        "NOT_FOUND"
    );
}

// r[verify platform.batch.same-as-alone]
#[tokio::test(flavor = "multi_thread")]
async fn each_operation_needs_its_own_capability() {
    let app = TestApp::new().await;
    let role = format!("ops-{}", uuid::Uuid::now_v7().simple());
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/root/roles/{role}"),
            Some(json!({"policies": [{"action": "konklav:tenants:manage", "effect": "allow"}]})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let operator = app.human("ops@example.com", PASSWORD).await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{operator}/global-assignments"),
        Some(json!({"role": role})),
    )
    .await;
    let token = app.login("ops@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let tenant = new_id();
    let operations = json!([
        {"method": "PUT", "path": format!("/tenants/{tenant}"), "body": {}},
        {"method": "PUT", "path": format!("/subjects/{}", new_id()), "body": {"kind": "human"}},
    ]);
    let auth = format!("Bearer {token}");
    let reply = app
        .send(
            Method::POST,
            "/v1/batch",
            &[("authorization", &auth)],
            Some(json!({"operations": operations})),
        )
        .await;
    assert_eq!(reply.code(), "FORBIDDEN", "{:?}", reply.body);
    assert_eq!(reply.body["error"]["operation"], 1);
    assert_eq!(
        app.control(Method::GET, &format!("/v1/tenants/{tenant}"), None)
            .await
            .code(),
        "NOT_FOUND",
        "nothing committed"
    );

    let unauthenticated = app
        .send(
            Method::POST,
            "/v1/batch",
            &[],
            Some(json!({"operations": [{"method": "PUT", "path": format!("/tenants/{tenant}"), "body": {}}]})),
        )
        .await;
    assert_eq!(unauthenticated.code(), "UNAUTHENTICATED");
}

// r[verify platform.batch.operations]
// r[verify platform.batch.limits]
#[tokio::test(flavor = "multi_thread")]
async fn batches_hold_a_bounded_list_of_writes() {
    let app = TestApp::with_auth(|auth| auth.batches.max_operations = 2).await;
    let subject = |id: &str| json!({"method": "PUT", "path": format!("/subjects/{id}"), "body": {"kind": "human"}});
    let refused = [
        json!([]),
        json!([{"method": "GET", "path": "/subjects"}]),
        json!([{"method": "POST", "path": "/batch", "body": {"operations": []}}]),
        json!([{"method": "PUT", "path": "subjects/x", "body": {}}]),
        json!([subject(&new_id()), subject(&new_id()), subject(&new_id())]),
    ];
    for operations in refused {
        let reply = batch(&app, operations.clone()).await;
        assert_eq!(
            reply.code(),
            "INVALID_REQUEST",
            "{operations}: {:?}",
            reply.body
        );
    }
    let reply = batch(&app, json!([subject(&new_id()), subject(&new_id())])).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);

    // Operations without a body, and with a query string.
    let id = new_id();
    let reply = batch(
        &app,
        json!([subject(&id), {"method": "POST", "path": format!("/subjects/{id}/disable")}]),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["results"][1]["body"]["state"], "disabled");
}

#[derive(QueryableByName)]
struct Exists {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    exists: bool,
}

/// A batch cut off by the request timeout commits nothing, and its
/// connection, dropped mid-transaction, isn't reused.
// r[verify platform.batch.atomic]
#[tokio::test(flavor = "multi_thread")]
async fn a_timed_out_batch_commits_nothing() {
    let app = TestApp::new().await;
    let running = app
        .serve_with(konklav_server::serve::Limits {
            request_timeout: Duration::from_millis(300),
            ..konklav_server::serve::Limits::DEFAULT
        })
        .await;

    // Another transaction holds the change feed's lock, so the batch's
    // first event waits past the timeout.
    let mut holder = app.db.pool().get().await.unwrap();
    holder
        .batch_execute("begin; select pg_advisory_xact_lock(event_lock_key());")
        .await
        .unwrap();

    let subject = new_id();
    let tenant = new_id();
    let http = reqwest::Client::new();
    let reply = http
        .post(format!("http://{}/v1/batch", running.control))
        .bearer_auth(CONTROL_TOKEN)
        .json(&json!({"operations": [
            {"method": "PUT", "path": format!("/subjects/{subject}"), "body": {"kind": "human"}},
            {"method": "PUT", "path": format!("/tenants/{tenant}"), "body": {}},
        ]}))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);

    holder.batch_execute("commit").await.unwrap();
    drop(holder);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut conn = app.db.pool().get().await.unwrap();
    for (table, id) in [("subject", &subject), ("tenant", &tenant)] {
        let found: Exists = diesel::sql_query(format!(
            "select exists(select 1 from {table} where id = '{id}') as exists"
        ))
        .get_result(&mut conn)
        .await
        .unwrap();
        assert!(!found.exists, "the {table} was not committed");
    }
    drop(conn);

    // The server still serves batches, on connections without a
    // transaction left open.
    for _ in 0..5 {
        let reply = http
            .post(format!("http://{}/v1/batch", running.control))
            .bearer_auth(CONTROL_TOKEN)
            .json(&json!({"operations": [
                {"method": "PUT", "path": format!("/subjects/{}", new_id()), "body": {"kind": "human"}},
            ]}))
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
    }
}

/// The bulk endpoints, imports and registered-scope changes, are ordinary
/// operations in a batch.
// r[verify platform.batch.same-as-alone]
#[tokio::test(flavor = "multi_thread")]
async fn bulk_endpoints_run_in_a_batch() {
    let app = TestApp::new().await;
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "document:read"}], "scope_kinds": [{"name": "document", "registered": true}]})),
    )
    .await;
    let (tenant, subject) = (new_id(), new_id());
    let reply = batch(
        &app,
        json!([
            {"method": "PUT", "path": format!("/tenants/{tenant}"), "body": {}},
            {"method": "POST", "path": "/import/subjects", "body": {"subjects": [{"id": subject, "kind": "human"}]}},
            {"method": "POST", "path": "/registered-scopes", "body": {"changes": [
                {"op": "record", "kind": "document", "id": "d-1", "tenant": tenant}
            ]}},
        ]),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["results"][1]["body"]["imported"], 1);
    assert_eq!(
        reply.body["results"][2]["body"]["scopes"][0]["tenant"],
        tenant.as_str()
    );
    assert_eq!(
        app.control(Method::GET, &format!("/v1/subjects/{subject}"), None)
            .await
            .status,
        StatusCode::OK
    );
}
