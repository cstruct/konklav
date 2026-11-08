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

async fn keyed(app: &TestApp, key: &str, operations: Value) -> common::Reply {
    app.control(
        Method::POST,
        "/v1/batch",
        Some(json!({"operations": operations, "idempotency_key": key})),
    )
    .await
}

// r[verify platform.batch.idempotency-key]
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_key_answers_the_first_batch() {
    let app = TestApp::new().await;
    let invite =
        json!([{"method": "POST", "path": "/invites", "body": {"email": "new@example.com"}}]);
    let first = keyed(&app, "k-1", invite.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let events = count(&app, "select count(*) as count from event").await;
    let again = keyed(&app, "k-1", invite.clone()).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(again.body, first.body, "the first answer");
    assert_eq!(
        count(
            &app,
            "select count(*) as count from challenge where purpose = 'invite'"
        )
        .await,
        1,
        "one invite"
    );
    assert_eq!(
        count(&app, "select count(*) as count from event").await,
        events,
        "nothing applied again"
    );

    let other =
        json!([{"method": "POST", "path": "/invites", "body": {"email": "other@example.com"}}]);
    assert_eq!(keyed(&app, "k-1", other).await.code(), "CONFLICT");

    // Keys are the caller's own: another operator's same key is another batch.
    let role = format!("ops-{}", uuid::Uuid::now_v7().simple());
    app.control(
        Method::PUT,
        &format!("/v1/tenants/root/roles/{role}"),
        Some(json!({"policies": [{"action": "konklav:invites:manage", "effect": "allow"}]})),
    )
    .await;
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
    let auth = format!("Bearer {token}");
    let theirs = app
        .send(
            Method::POST,
            "/v1/batch",
            &[("authorization", &auth)],
            Some(json!({"operations": invite, "idempotency_key": "k-1"})),
        )
        .await;
    assert_eq!(theirs.status, StatusCode::OK, "{:?}", theirs.body);
    assert_ne!(
        theirs.body["results"][0]["body"]["invite_id"],
        first.body["results"][0]["body"]["invite_id"]
    );
}

// r[verify platform.batch.idempotency-key]
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_batch_is_not_remembered() {
    let app = TestApp::new().await;
    let subject = new_id();
    let operations = json!([
        {"method": "PUT", "path": format!("/subjects/{subject}"), "body": {"kind": "service"}},
        {"method": "POST", "path": format!("/subjects/{subject}/global-assignments"), "body": {"role": "auditor"}},
    ]);
    assert_eq!(
        keyed(&app, "k-2", operations.clone()).await.code(),
        "NOT_FOUND"
    );
    app.control(
        Method::PUT,
        "/v1/tenants/root/roles/auditor",
        Some(json!({"policies": []})),
    )
    .await;
    let reply = keyed(&app, "k-2", operations).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
}

// r[verify platform.batch.idempotency-key]
#[tokio::test(flavor = "multi_thread")]
async fn a_repeat_shows_new_secrets() {
    let app = TestApp::new().await;
    let service = new_id();
    let operations = json!([
        {"method": "PUT", "path": format!("/subjects/{service}"), "body": {"kind": "service"}},
        {"method": "POST", "path": format!("/subjects/{service}/credentials"), "body": {"kind": "secret_key"}},
    ]);
    let first = keyed(&app, "k-3", operations.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let again = keyed(&app, "k-3", operations).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);

    let (first, again) = (
        &first.body["results"][1]["body"],
        &again.body["results"][1]["body"],
    );
    assert_eq!(
        again["credential"]["id"], first["credential"]["id"],
        "the same credential"
    );
    let login = |presented: &Value| {
        let (key_id, secret) = presented.as_str().unwrap().split_once('.').unwrap();
        let body = json!({"key_id": key_id, "secret": secret});
        let app = &app;
        async move { app.post("/v1/login/secret-key", body).await }
    };
    for slot in ["a", "b"] {
        assert_ne!(again["secret_keys"][slot], first["secret_keys"][slot]);
        assert_eq!(
            login(&again["secret_keys"][slot]).await.status,
            StatusCode::OK
        );
        assert_eq!(
            login(&first["secret_keys"][slot]).await.code(),
            "INVALID_CREDENTIALS"
        );
    }
    let stored = count(
        &app,
        "select count(*) as count from batch_result where answer::text like '%secret_keys\": {%'",
    )
    .await;
    assert_eq!(stored, 0, "secrets aren't remembered");
}

// r[verify platform.batch.idempotency-key]
// r[verify authn.invite.link-only]
#[tokio::test(flavor = "multi_thread")]
async fn a_repeat_shows_a_link_only_invite_a_new_token() {
    let app = TestApp::new().await;
    let operations = json!([{"method": "POST", "path": "/invites", "body": {}}]);
    let first = keyed(&app, "k-invite", operations.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let again = keyed(&app, "k-invite", operations).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    let (first, again) = (
        &first.body["results"][0]["body"],
        &again.body["results"][0]["body"],
    );
    assert_eq!(again["invite_id"], first["invite_id"], "the same invite");
    assert_ne!(again["token"], first["token"]);
    let preview = |token: &Value| {
        let app = &app;
        let body = json!({"token": token});
        async move { app.post("/v1/invites/preview", body).await }
    };
    assert_eq!(preview(&again["token"]).await.status, StatusCode::OK);
    assert_eq!(preview(&first["token"]).await.code(), "INVALID_CREDENTIALS");
    assert_eq!(
        count(
            &app,
            "select count(*) as count from challenge where purpose = 'invite'"
        )
        .await,
        1
    );
    let stored = count(
        &app,
        "select count(*) as count from batch_result where answer::text like '%\"token\": \"%'",
    )
    .await;
    assert_eq!(stored, 0, "tokens aren't remembered");
}

// r[verify platform.batch.key-lifetime]
// r[verify retention.batch-results]
#[tokio::test(flavor = "multi_thread")]
async fn keys_are_forgotten_once_their_lifetime_passes() {
    let app = TestApp::new().await;
    let invite =
        json!([{"method": "POST", "path": "/invites", "body": {"email": "new@example.com"}}]);
    for seconds in [0, 3601] {
        let reply = app
            .control(
                Method::POST,
                "/v1/batch",
                Some(json!({"operations": invite, "idempotency_key": "k", "idempotency_seconds": seconds})),
            )
            .await;
        assert_eq!(reply.code(), "INVALID_REQUEST", "{seconds}");
    }
    let reply = app
        .control(
            Method::POST,
            "/v1/batch",
            Some(json!({"operations": invite, "idempotency_key": "k-4", "idempotency_seconds": 3600})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let lifetime = count(
        &app,
        "select extract(epoch from expires_at - created_at)::bigint as count from batch_result",
    )
    .await;
    assert!((3599..=3600).contains(&lifetime), "{lifetime}");

    let mut conn = app.db.pool().get().await.unwrap();
    conn.batch_execute("update batch_result set expires_at = now() - interval '1 second'")
        .await
        .unwrap();
    drop(conn);
    let reply = keyed(&app, "k-4", invite.clone()).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(
        count(
            &app,
            "select count(*) as count from challenge where purpose = 'invite'"
        )
        .await,
        2,
        "an expired key no longer stops a repeat"
    );

    let mut conn = app.db.pool().get().await.unwrap();
    conn.batch_execute("update batch_result set expires_at = now() - interval '1 second'")
        .await
        .unwrap();
    let swept = konklav_store::sweep::batch_results(&mut conn, chrono::Utc::now(), 100)
        .await
        .unwrap();
    assert_eq!(swept, 1);
}
