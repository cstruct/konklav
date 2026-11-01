#![allow(clippy::too_many_lines)]

//! Registered scopes end to end: a relying system records which tenant and
//! projects a document belongs to, then asks about the document alone.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

async fn tenant(app: &TestApp) -> String {
    let tenant = uuid::Uuid::now_v7().to_string();
    let created = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    tenant
}

/// A member of `tenant` holding `role`, tenant-wide or at `scope`, logged
/// in to it; returns a tenant token.
async fn member(app: &TestApp, tenant: &str, role: &str, scope: Option<Value>) -> String {
    let email = format!("{}@example.com", uuid::Uuid::now_v7().simple());
    let subject = app.human(&email, PASSWORD).await;
    let membership = uuid::Uuid::now_v7().to_string();
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": subject, "tenant": tenant})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    let mut assignment = json!({"role": role});
    if let Some(scope) = scope {
        assignment["scope"] = scope;
    }
    let reply = app
        .control(
            Method::POST,
            &format!("/v1/memberships/{membership}/assignments"),
            Some(assignment),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    let login = app.login(&email, PASSWORD).await;
    let auth = format!("Bearer {}", login.body["access_token"].as_str().unwrap());
    let selected = app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": tenant})),
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    selected.body["access_token"].as_str().unwrap().to_owned()
}

async fn role(app: &TestApp, tenant: &str, key: &str, scope_bound: bool) {
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}/roles/{key}"),
            Some(json!({"policies": [
                {"action": "document:read", "effect": "allow", "scope_bound": scope_bound}
            ]})),
        )
        .await;
    assert!(reply.status.is_success(), "{:?}", reply.body);
}

async fn check(app: &TestApp, service: &str, token: &str, id: &str) -> Value {
    let auth = format!("Bearer {service}");
    let reply = app
        .send(
            Method::POST,
            "/v1/check",
            &[("authorization", &auth)],
            Some(json!({"token": token, "requirements": {"scopes": [
                {"kind": "document", "id": id, "actions": ["document:read"]}
            ]}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    reply.body
}

async fn record(app: &TestApp, id: &str, tenant: &str, projects: &[&str]) -> common::Reply {
    let containers: Vec<Value> = projects
        .iter()
        .map(|p| json!({"kind": "project", "id": p}))
        .collect();
    app.control(
        Method::PUT,
        &format!("/v1/registered-scopes/document/{id}"),
        Some(json!({"tenant": tenant, "containers": containers})),
    )
    .await
}

// r[verify authz.registered.evaluation]
// r[verify authz.registered.shares]
// r[verify authz.registered.unknown-denies]
// r[verify authz.registered.tenant-fixed]
// r[verify authz.registered.api]
// r[verify authz.compile.registered-kinds]
// r[verify authz.resource-context.external]
#[tokio::test(flavor = "multi_thread")]
async fn requirements_name_a_registered_scope_alone() {
    let app = TestApp::new().await;
    let reply = app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({
                "actions": [{"name": "document:read"}],
                "scope_kinds": [{"name": "project"}, {"name": "document", "registered": true}],
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let owner = tenant(&app).await;
    let other = tenant(&app).await;
    role(&app, &owner, "project-reader", true).await;
    role(&app, &other, "reader", false).await;
    let p1_reader = member(
        &app,
        &owner,
        "project-reader",
        Some(json!({"kind": "project", "id": "p-1"})),
    )
    .await;
    let outsider = member(&app, &other, "reader", None).await;
    let service = app.service_token().await;

    let recorded = record(&app, "d-1", &owner, &["p-1"]).await;
    assert_eq!(recorded.status, StatusCode::OK, "{:?}", recorded.body);
    assert_eq!(recorded.body["tenant"], json!(owner));
    assert!(recorded.body["cursor"].is_i64());

    assert_eq!(
        check(&app, &service, &p1_reader, "d-1").await["decision"],
        "allow"
    );
    assert_eq!(
        check(&app, &service, &outsider, "d-1").await["decision"],
        "deny",
        "another tenant's reader can't read it by naming its id"
    );
    let unknown = check(&app, &service, &p1_reader, "d-9").await;
    assert_eq!(
        unknown["reason"],
        json!({"unknown_scope": {"kind": "document", "id": "d-9"}}),
        "{unknown:?}"
    );

    // Sharing the project with the other tenant lets its readers in.
    let share = uuid::Uuid::now_v7().to_string();
    let offered = app
        .control(
            Method::PUT,
            &format!("/v1/shares/{share}"),
            Some(json!({
                "owner": owner,
                "scope": {"kind": "project", "id": "p-1"},
                "recipient": other,
                "actions": ["document:read"],
            })),
        )
        .await;
    assert_eq!(offered.status, StatusCode::OK, "{:?}", offered.body);
    app.control(Method::POST, &format!("/v1/shares/{share}/accept"), None)
        .await;
    let shared = check(&app, &service, &outsider, "d-1").await;
    assert_eq!(shared["decision"], "allow", "{shared:?}");
    assert_eq!(shared["obligations"][0]["id"], "p-1");

    // Moving the document out of p-1 takes both grants away.
    record(&app, "d-1", &owner, &["p-2"]).await;
    assert_eq!(
        check(&app, &service, &p1_reader, "d-1").await["decision"],
        "deny"
    );
    assert_eq!(
        check(&app, &service, &outsider, "d-1").await["decision"],
        "deny"
    );

    // The relying surface serves the record; the entitlement set names the
    // registered kinds.
    let auth = format!("Bearer {service}");
    let served = app
        .send(
            Method::GET,
            "/v1/registered-scopes/document/d-1",
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(served.status, StatusCode::OK, "{:?}", served.body);
    assert_eq!(
        served.body["containers"],
        json!([{"kind": "project", "id": "p-2"}])
    );
    assert_eq!(served.body["state"], "active");
    let missing = app
        .send(
            Method::GET,
            "/v1/registered-scopes/document/d-9",
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let subject = app.verify(&p1_reader).await.sub;
    let set = app
        .send(
            Method::GET,
            &format!("/v1/entitlements/{subject}/{owner}"),
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(set.body["registered_kinds"], json!(["document"]));

    // Its tenant is fixed, even after removal.
    assert_eq!(
        record(&app, "d-1", &other, &[]).await.status,
        StatusCode::CONFLICT
    );
    let removed = app
        .control(Method::DELETE, "/v1/registered-scopes/document/d-1", None)
        .await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);
    assert_eq!(removed.body["state"], "removed");
    assert_eq!(
        record(&app, "d-1", &other, &[]).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        check(&app, &service, &p1_reader, "d-1").await["reason"],
        json!({"unknown_scope": {"kind": "document", "id": "d-1"}})
    );
}

// r[verify authz.registered.batch]
// r[verify authz.registered.capability]
#[tokio::test(flavor = "multi_thread")]
async fn batches_record_many_scopes_at_once() {
    let app = TestApp::new().await;
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({
            "scope_kinds": [{"name": "project"}, {"name": "document", "registered": true}],
        })),
    )
    .await;
    let owner = tenant(&app).await;
    let changes: Vec<Value> = (0..200)
        .map(|i| json!({"op": "record", "kind": "document", "id": format!("d-{i}"), "tenant": owner}))
        .chain([json!({"op": "remove", "kind": "document", "id": "d-unknown"})])
        .collect();
    let reply = app
        .control(
            Method::POST,
            "/v1/registered-scopes",
            Some(json!({"changes": changes})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["scopes"].as_array().unwrap().len(), 201);
    assert_eq!(reply.body["scopes"][200], Value::Null);
    assert!(reply.body["cursor"].is_i64());

    let failed = app
        .control(
            Method::POST,
            "/v1/registered-scopes",
            Some(json!({"changes": [
                {"op": "record", "kind": "document", "id": "d-new", "tenant": owner},
                {"op": "record", "kind": "project", "id": "p-1", "tenant": owner},
            ]})),
        )
        .await;
    assert_eq!(failed.status, StatusCode::CONFLICT, "{:?}", failed.body);
    let served = app
        .send(
            Method::GET,
            "/v1/registered-scopes/document/d-new",
            &[(
                "authorization",
                &format!("Bearer {}", app.service_token().await),
            )],
            None,
        )
        .await;
    assert_eq!(served.status, StatusCode::NOT_FOUND, "all or nothing");

    // Writes need the capability.
    app.human("someone@example.com", PASSWORD).await;
    let login = app.login("someone@example.com", PASSWORD).await;
    let token = login.body["access_token"].as_str().unwrap();
    let refused = app
        .send(
            Method::PUT,
            "/v1/registered-scopes/document/d-1",
            &[("authorization", &format!("Bearer {token}"))],
            Some(json!({"tenant": owner})),
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.body);
}
