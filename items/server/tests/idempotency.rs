//! Creates on the control plane are idempotent on the ids callers choose
//! (`platform.idempotency.client-ids`): an identical repeat answers 200 and
//! applies nothing again, a conflicting one `CONFLICT`.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use diesel::QueryableByName;
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

fn without_cursor(body: &Value) -> Value {
    let mut body = body.clone();
    body.as_object_mut().unwrap().remove("cursor");
    body
}

async fn subject(app: &TestApp, kind: &str) -> String {
    let id = new_id();
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/subjects/{id}"),
            Some(json!({"kind": kind})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    id
}

async fn create_credential(app: &TestApp, subject: &str, body: Value) -> common::Reply {
    app.control(
        Method::POST,
        &format!("/v1/subjects/{subject}/credentials"),
        Some(body),
    )
    .await
}

// r[verify platform.idempotency.client-ids]
#[tokio::test(flavor = "multi_thread")]
async fn repeated_credentials_answer_the_existing_one() {
    let app = TestApp::new().await;
    let person = subject(&app, "human").await;
    let id = new_id();
    let password = json!({"id": id, "kind": "password", "identifier": "Ada@example.com", "password": PASSWORD});
    let first = create_credential(&app, &person, password.clone()).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    let again = create_credential(&app, &person, password).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(again.body["credential"], first.body["credential"]);

    let other_password = json!({"id": id, "kind": "password", "identifier": "ada@example.com", "password": "another password"});
    assert_eq!(
        create_credential(&app, &person, other_password)
            .await
            .code(),
        "CONFLICT"
    );
    let other_kind = json!({"id": id, "kind": "email_link", "identifier": "ada@example.com"});
    assert_eq!(
        create_credential(&app, &person, other_kind).await.code(),
        "CONFLICT"
    );
    let elsewhere = subject(&app, "human").await;
    let moved = json!({"id": id, "kind": "password", "identifier": "ada@example.com", "password": PASSWORD});
    assert_eq!(
        create_credential(&app, &elsewhere, moved).await.code(),
        "CONFLICT"
    );

    let link = json!({"id": new_id(), "kind": "email_link", "identifier": "grace@example.com"});
    assert_eq!(
        create_credential(&app, &person, link.clone()).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        create_credential(&app, &person, link).await.status,
        StatusCode::OK
    );

    let revoked = app
        .control(Method::POST, &format!("/v1/credentials/{id}/revoke"), None)
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);
    let after = json!({"id": id, "kind": "password", "identifier": "ada@example.com", "password": PASSWORD});
    assert_eq!(
        create_credential(&app, &person, after).await.code(),
        "CONFLICT"
    );
}

// r[verify platform.idempotency.client-ids]
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_secret_key_shows_new_secrets() {
    let app = TestApp::new().await;
    let service = subject(&app, "service").await;
    let id = new_id();
    let body = json!({"id": id, "kind": "secret_key"});
    let first = create_credential(&app, &service, body.clone()).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    let again = create_credential(&app, &service, body).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);

    let login = |presented: &Value| {
        let (key_id, secret) = presented.as_str().unwrap().split_once('.').unwrap();
        let body = json!({"key_id": key_id, "secret": secret});
        let app = &app;
        async move { app.post("/v1/login/secret-key", body).await }
    };
    for slot in ["a", "b"] {
        let old = &first.body["secret_keys"][slot];
        let new = &again.body["secret_keys"][slot];
        assert_ne!(old, new);
        assert_eq!(login(new).await.status, StatusCode::OK, "slot {slot}");
        assert_eq!(
            login(old).await.code(),
            "INVALID_CREDENTIALS",
            "slot {slot}"
        );
    }

    let expiring = json!({"id": id, "kind": "secret_key", "expires_at": "2099-01-01T00:00:00Z"});
    assert_eq!(
        create_credential(&app, &service, expiring).await.code(),
        "CONFLICT"
    );
}

// r[verify platform.idempotency.client-ids]
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_password_replacement_answers_the_replacement() {
    let app = TestApp::new().await;
    let person = subject(&app, "human").await;
    let old = new_id();
    let created = create_credential(
        &app,
        &person,
        json!({"id": old, "kind": "password", "identifier": "ada@example.com", "password": PASSWORD}),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);

    let replace = |body: Value| {
        let app = &app;
        let uri = format!("/v1/credentials/{old}/replace");
        async move { app.control(Method::POST, &uri, Some(body)).await }
    };
    let new = new_id();
    let first = replace(json!({"id": new, "password": "a brand new password"})).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    let again = replace(json!({"id": new, "password": "a brand new password"})).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(without_cursor(&again.body), without_cursor(&first.body));
    assert_eq!(
        replace(json!({"id": new, "password": "yet another password"}))
            .await
            .code(),
        "CONFLICT"
    );
}

async fn tenant_with_role(app: &TestApp) -> String {
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "document:read"}], "scope_kinds": [{"name": "project"}]})),
    )
    .await;
    let tenant = new_id();
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    for (tenant, key) in [(tenant.as_str(), "reader"), ("root", "auditor")] {
        let reply = app
            .control(
                Method::PUT,
                &format!("/v1/tenants/{tenant}/roles/{key}"),
                Some(json!({"policies": [{"action": "document:read", "effect": "allow"}]})),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    }
    tenant
}

// r[verify platform.idempotency.client-ids]
#[tokio::test(flavor = "multi_thread")]
async fn repeated_assignments_answer_the_existing_one() {
    let app = TestApp::new().await;
    let tenant = tenant_with_role(&app).await;
    let person = app.human("ada@example.com", PASSWORD).await;
    let membership = new_id();
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": person, "tenant": tenant})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);

    let assign = |body: Value| {
        let app = &app;
        let uri = format!("/v1/memberships/{membership}/assignments");
        async move { app.control(Method::POST, &uri, Some(body)).await }
    };
    let id = new_id();
    let first = assign(json!({"id": id, "role": "reader"})).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    assert_eq!(first.body["id"], id);
    assert!(first.body["cursor"].is_i64());
    let again = assign(json!({"id": id, "role": "reader"})).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(without_cursor(&again.body), without_cursor(&first.body));

    let scoped = json!({"id": id, "role": "reader", "scope": {"kind": "project", "id": "p1"}});
    assert_eq!(assign(scoped).await.code(), "CONFLICT");
    let same_role_new_id = json!({"id": new_id(), "role": "reader"});
    assert_eq!(assign(same_role_new_id).await.code(), "CONFLICT");
    // Without an id, assigning what is assigned answers the existing one.
    let unnamed = assign(json!({"role": "reader"})).await;
    assert_eq!(unnamed.status, StatusCode::OK, "{:?}", unnamed.body);
    assert_eq!(unnamed.body["id"], id);

    let global = |body: Value| {
        let app = &app;
        let uri = format!("/v1/subjects/{person}/global-assignments");
        async move { app.control(Method::POST, &uri, Some(body)).await }
    };
    let id = new_id();
    let first = global(json!({"id": id, "role": "auditor"})).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    let again = global(json!({"id": id, "role": "auditor"})).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(again.body["id"], id);
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

// r[verify platform.idempotency.client-ids]
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_invite_is_not_delivered_again() {
    let app = TestApp::new().await;
    let tenant = tenant_with_role(&app).await;
    let invite = |body: Value| {
        let app = &app;
        async move { app.control(Method::POST, "/v1/invites", Some(body)).await }
    };
    let id = new_id();
    let body = json!({"id": id, "email": "new@example.com", "tenant": tenant, "roles": ["reader"]});
    let first = invite(body.clone()).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    assert_eq!(first.body["invite_id"], id);
    let again = invite(body).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(without_cursor(&again.body), without_cursor(&first.body));
    assert!(again.body["cursor"].is_null());

    let mut conn = app.db.pool().get().await.unwrap();
    let deliveries: Count = diesel::sql_query(
        "select count(*) as count from event
         where kind = 'delivery.requested' and payload->>'recipient' = 'new@example.com'",
    )
    .get_result(&mut conn)
    .await
    .unwrap();
    assert_eq!(deliveries.count, 1);

    let other = json!({"id": id, "email": "someone@example.com", "tenant": tenant});
    assert_eq!(invite(other).await.code(), "CONFLICT");
}
