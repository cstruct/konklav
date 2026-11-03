#![allow(clippy::too_many_lines)]

//! Shares end to end: an owner tenant offers one of its scopes, the
//! recipient accepts it, and the recipient's members get decided on it
//! through the check API, with the share's attributes as obligations.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

struct World {
    app: TestApp,
    owner: String,
    recipient: String,
    service: String,
    /// A recipient member reading documents tenant-wide.
    reader: String,
    /// A recipient member reading documents only at project q-3.
    q3_reader: String,
}

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

/// A member of `tenant` holding `role`, tenant-wide or at `scope`; returns
/// their email.
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
    email
}

async fn world() -> World {
    let app = TestApp::new().await;
    let reply = app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({
                "actions": [{"name": "document:read"}, {"name": "document:write"}],
                "groups": [{"name": "document:all", "actions": ["document:read", "document:write"]}],
                "scope_kinds": [{"name": "project"}],
                "facts": [{"key": "data_range", "target": "share", "type": "date_range"}]
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let owner = tenant(&app).await;
    let recipient = tenant(&app).await;
    for (key, scope_bound) in [("reader", false), ("project-reader", true)] {
        let reply = app
            .control(
                Method::PUT,
                &format!("/v1/tenants/{recipient}/roles/{key}"),
                Some(json!({"policies": [
                    {"action": "document:read", "effect": "allow", "scope_bound": scope_bound}
                ]})),
            )
            .await;
        assert!(reply.status.is_success(), "{:?}", reply.body);
        // r[verify platform.idempotency.write-cursor]
        assert!(
            reply.body["cursor"].is_i64(),
            "role writes report their cursor"
        );
    }
    let reader = member(&app, &recipient, "reader", None).await;
    let q3_reader = member(
        &app,
        &recipient,
        "project-reader",
        Some(json!({"kind": "project", "id": "q-3"})),
    )
    .await;
    let service = app.service_token().await;
    World {
        app,
        owner,
        recipient,
        service,
        reader,
        q3_reader,
    }
}

async fn tenant_token(world: &World, email: &str) -> String {
    let login = world.app.login(email, PASSWORD).await;
    let auth = format!("Bearer {}", login.body["access_token"].as_str().unwrap());
    let selected = world
        .app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": world.recipient})),
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    selected.body["access_token"].as_str().unwrap().to_owned()
}

async fn check(world: &World, token: &str, actions: &[&str]) -> Value {
    let auth = format!("Bearer {}", world.service);
    let reply = world
        .app
        .send(
            Method::POST,
            "/v1/check",
            &[("authorization", &auth)],
            Some(json!({"token": token, "requirements": {"scopes": [
                {"tenant": world.owner, "kind": "project", "id": "p-17", "actions": actions}
            ]}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    reply.body
}

fn terms(world: &World) -> Value {
    json!({
        "owner": world.owner,
        "scope": {"kind": "project", "id": "p-17"},
        "recipient": world.recipient,
        "actions": ["document:all"],
        "attributes": {"data_range": {"from": "2026-01-01", "until": "2026-06-30"}}
    })
}

// r[verify authz.share.shape]
// r[verify authz.share.acceptance]
// r[verify authz.share.ceiling]
// r[verify authz.share.requirements]
// r[verify authz.share.attributes]
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_share_reaches_the_recipients_members() {
    let world = world().await;
    let app = &world.app;
    let share = uuid::Uuid::now_v7().to_string();
    let reader = tenant_token(&world, &world.reader).await;
    let q3_reader = tenant_token(&world, &world.q3_reader).await;

    let offered = app
        .control(
            Method::PUT,
            &format!("/v1/shares/{share}"),
            Some(terms(&world)),
        )
        .await;
    assert_eq!(offered.status, StatusCode::OK, "{:?}", offered.body);
    assert_eq!(offered.body["state"], "offered");
    assert!(offered.body["cursor"].is_i64());
    assert_eq!(
        check(&world, &reader, &["document:read"]).await["decision"],
        "deny",
        "an offered share grants nothing"
    );

    let accepted = app
        .control(Method::POST, &format!("/v1/shares/{share}/accept"), None)
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    assert_eq!(accepted.body["state"], "accepted");
    let allowed = check(&world, &reader, &["document:read"]).await;
    assert_eq!(allowed["decision"], "allow", "{allowed:?}");
    assert_eq!(
        allowed["obligations"],
        json!([{
            "share": share,
            "tenant": world.owner,
            "kind": "project",
            "id": "p-17",
            "attributes": {"data_range": {"from": "2026-01-01", "until": "2026-06-30"}}
        }])
    );
    assert_eq!(
        check(&world, &reader, &["document:write"]).await["decision"],
        "deny",
        "the reader doesn't hold document:write, though the share allows it"
    );
    assert_eq!(
        check(&world, &q3_reader, &["document:read"]).await["decision"],
        "deny",
        "a tenant-wide share needs the action tenant-wide"
    );

    // The entitlement set lists the share.
    let subject = app.verify(&reader).await.sub;
    let auth = format!("Bearer {}", world.service);
    let set = app
        .send(
            Method::GET,
            &format!("/v1/entitlements/{subject}/{}", world.recipient),
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(
        set.body["shared"][0]["share"],
        json!(share),
        "{:?}",
        set.body
    );
    assert_eq!(set.body["shared"][0]["actions"], json!(["document:read"]));

    // Narrowing it to project q-3 offers it again: nothing until accepted.
    let mut at_q3 = terms(&world);
    at_q3["recipient_scope"] = json!({"kind": "project", "id": "q-3"});
    let reoffered = app
        .control(Method::PUT, &format!("/v1/shares/{share}"), Some(at_q3))
        .await;
    assert_eq!(reoffered.body["state"], "offered", "{:?}", reoffered.body);
    assert_eq!(
        check(&world, &q3_reader, &["document:read"]).await["decision"],
        "deny"
    );
    app.control(Method::POST, &format!("/v1/shares/{share}/accept"), None)
        .await;
    assert_eq!(
        check(&world, &q3_reader, &["document:read"]).await["decision"],
        "allow"
    );

    let listed = app
        .control(
            Method::GET,
            &format!("/v1/tenants/{}/shares?side=recipient", world.recipient),
            None,
        )
        .await;
    assert_eq!(listed.body["shares"].as_array().unwrap().len(), 1);
    let none = app
        .control(
            Method::GET,
            &format!("/v1/tenants/{}/shares?side=owner", world.recipient),
            None,
        )
        .await;
    assert_eq!(none.body["shares"], json!([]));

    // Revoking is final.
    let revoked = app
        .control(
            Method::POST,
            &format!("/v1/shares/{share}/revoke"),
            Some(json!({"by": "recipient"})),
        )
        .await;
    assert_eq!(revoked.body["state"], "revoked", "{:?}", revoked.body);
    assert_eq!(revoked.body["revoked_by"], "recipient");
    assert_eq!(
        check(&world, &q3_reader, &["document:read"]).await["decision"],
        "deny"
    );
    let again = app
        .control(Method::POST, &format!("/v1/shares/{share}/accept"), None)
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{:?}", again.body);
    let changed = app
        .control(
            Method::PUT,
            &format!("/v1/shares/{share}"),
            Some(terms(&world)),
        )
        .await;
    assert_eq!(changed.status, StatusCode::CONFLICT, "{:?}", changed.body);
}

// r[verify authz.share.unique]
// r[verify authz.share.shape]
// r[verify authz.share.attributes]
#[tokio::test(flavor = "multi_thread")]
async fn shares_are_validated_when_offered() {
    let world = world().await;
    let app = &world.app;
    let offer = |body: Value| async move {
        app.control(
            Method::PUT,
            &format!("/v1/shares/{}", uuid::Uuid::now_v7()),
            Some(body),
        )
        .await
    };
    let first = offer(terms(&world)).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let duplicate = offer(terms(&world)).await;
    assert_eq!(
        duplicate.status,
        StatusCode::CONFLICT,
        "{:?}",
        duplicate.body
    );

    for (change, why) in [
        (json!({"recipient": world.owner}), "sharing with itself"),
        (json!({"actions": ["konklav:control:all"]}), "a capability"),
        (
            json!({"actions": ["document:delete"]}),
            "an undeclared action",
        ),
        (json!({"actions": []}), "no actions"),
        (
            json!({"scope": {"kind": "folder", "id": "f-1"}}),
            "an undeclared scope kind",
        ),
        (
            json!({"attributes": {"region": "eu"}}),
            "an undeclared attribute",
        ),
        (
            json!({"attributes": {"data_range": {"from": "2026-07-01", "until": "2026-06-30"}}}),
            "a backwards date range",
        ),
        (
            json!({"valid_from": "2026-12-01T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z"}),
            "a backwards validity period",
        ),
    ] {
        let mut body = terms(&world);
        body["scope"]["id"] = json!(uuid::Uuid::now_v7().to_string());
        for (key, value) in change.as_object().unwrap() {
            body[key] = value.clone();
        }
        let reply = offer(body).await;
        assert!(
            reply.status.is_client_error(),
            "{why}: {} {:?}",
            reply.status,
            reply.body
        );
    }

    // Share attributes can't be portable.
    let catalog = app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({
                "actions": [{"name": "document:read"}, {"name": "document:write"}],
                "groups": [{"name": "document:all", "actions": ["document:read", "document:write"]}],
                "scope_kinds": [{"name": "project"}],
                "facts": [{"key": "data_range", "target": "share", "type": "date_range", "portable": true}]
            })),
        )
        .await;
    assert!(catalog.status.is_client_error(), "{:?}", catalog.body);
}

// r[verify authz.share.events]
#[tokio::test(flavor = "multi_thread")]
async fn share_changes_are_on_the_change_feed() {
    let world = world().await;
    let app = &world.app;
    let share = uuid::Uuid::now_v7().to_string();
    let offered = app
        .control(
            Method::PUT,
            &format!("/v1/shares/{share}"),
            Some(terms(&world)),
        )
        .await;
    let after = offered.body["cursor"].as_i64().unwrap() - 10;
    app.control(Method::POST, &format!("/v1/shares/{share}/accept"), None)
        .await;
    let auth = format!("Bearer {}", world.service);
    let feed = app
        .send(
            Method::GET,
            &format!("/v1/events/batch?after={after}&kinds=share.changed,entitlements.changed"),
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(feed.status, StatusCode::OK, "{:?}", feed.body);
    let events = feed.body["events"].as_array().unwrap();
    let states: Vec<&Value> = events
        .iter()
        .filter(|e| e["kind"] == "share.changed" && e["payload"]["share"] == json!(share))
        .map(|e| &e["payload"]["state"])
        .collect();
    assert_eq!(
        states,
        [&json!("offered"), &json!("accepted")],
        "{events:?}"
    );
    let shared = &events
        .iter()
        .find(|e| e["kind"] == "share.changed")
        .unwrap()["payload"];
    assert_eq!(shared["owner"], json!(world.owner));
    assert_eq!(shared["recipient"], json!(world.recipient));
    assert!(events.iter().any(|e| {
        e["kind"] == "entitlements.changed"
            && e["payload"]["all"] == json!(true)
            && e["payload"]["tenant"] == json!(world.recipient)
    }));
}

// r[verify authz.share.validity]
// r[verify authz.share.ceiling]
#[tokio::test(flavor = "multi_thread")]
async fn shares_grant_nothing_outside_their_period_or_from_inactive_owners() {
    let world = world().await;
    let app = &world.app;
    let reader = tenant_token(&world, &world.reader).await;
    let share = uuid::Uuid::now_v7().to_string();
    let mut later = terms(&world);
    later["valid_from"] = json!("2099-01-01T00:00:00Z");
    app.control(Method::PUT, &format!("/v1/shares/{share}"), Some(later))
        .await;
    app.control(Method::POST, &format!("/v1/shares/{share}/accept"), None)
        .await;
    assert_eq!(
        check(&world, &reader, &["document:read"]).await["decision"],
        "deny",
        "not yet valid"
    );
    let mut now = terms(&world);
    now["valid_until"] = json!("2099-01-01T00:00:00Z");
    app.control(Method::PUT, &format!("/v1/shares/{share}"), Some(now))
        .await;
    app.control(Method::POST, &format!("/v1/shares/{share}/accept"), None)
        .await;
    assert_eq!(
        check(&world, &reader, &["document:read"]).await["decision"],
        "allow"
    );

    let suspended = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{}/state", world.owner),
            Some(json!({"state": "suspended"})),
        )
        .await;
    assert!(suspended.status.is_success(), "{:?}", suspended.body);
    assert_eq!(
        check(&world, &reader, &["document:read"]).await["decision"],
        "deny",
        "a suspended owner shares nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn shares_can_be_read_back() {
    let world = world().await;
    let app = &world.app;
    let share = uuid::Uuid::now_v7().to_string();
    let mut offered = app
        .control(
            Method::PUT,
            &format!("/v1/shares/{share}"),
            Some(terms(&world)),
        )
        .await
        .body;
    offered.as_object_mut().unwrap().remove("cursor");

    let read = app
        .control(Method::GET, &format!("/v1/shares/{share}"), None)
        .await;
    assert_eq!(read.status, StatusCode::OK, "{:?}", read.body);
    assert_eq!(read.body, offered);

    let unknown = app
        .control(
            Method::GET,
            &format!("/v1/shares/{}", uuid::Uuid::now_v7()),
            None,
        )
        .await;
    assert_eq!(unknown.code(), "NOT_FOUND");
}
