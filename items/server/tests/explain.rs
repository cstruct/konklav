#![allow(clippy::too_many_lines)]

//! Explaining decisions through the control plane.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

struct World {
    app: TestApp,
    tenant: String,
    subject: String,
    email: String,
    service: String,
}

/// A member holding `editor` (allows `document:write` at p1, priority 1)
/// and `frozen` (denies it at p1, priority 5), and `reader` tenant-wide.
async fn world() -> World {
    let app = TestApp::new().await;
    let reply = app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({
                "actions": [{"name": "document:read"}, {"name": "document:write"}],
                "scope_kinds": [{"name": "project"}],
                "session_flags": [{"name": "personal_only", "kind": "restrictive", "requestable": true}]
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let tenant = uuid::Uuid::now_v7().to_string();
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        Some(json!({})),
    )
    .await;
    for (key, priority, policy) in [
        (
            "editor",
            1,
            json!({"action": "document:write", "effect": "allow", "scope_bound": true}),
        ),
        (
            "frozen",
            5,
            json!({"action": "document:write", "effect": "deny", "scope_bound": true}),
        ),
        (
            "reader",
            0,
            json!({"action": "document:read", "effect": "allow"}),
        ),
    ] {
        let reply = app
            .control(
                Method::PUT,
                &format!("/v1/tenants/{tenant}/roles/{key}"),
                Some(json!({"priority": priority, "policies": [policy]})),
            )
            .await;
        assert!(reply.status.is_success(), "{:?}", reply.body);
    }
    let email = format!("{}@example.com", uuid::Uuid::now_v7().simple());
    let subject = app.human(&email, PASSWORD).await;
    let membership = uuid::Uuid::now_v7().to_string();
    app.control(
        Method::PUT,
        &format!("/v1/memberships/{membership}"),
        Some(json!({"subject": subject, "tenant": tenant})),
    )
    .await;
    for (role, scope) in [
        ("editor", json!({"kind": "project", "id": "p1"})),
        ("frozen", json!({"kind": "project", "id": "p1"})),
        ("reader", Value::Null),
    ] {
        let mut body = json!({"role": role});
        if !scope.is_null() {
            body["scope"] = scope;
        }
        let reply = app
            .control(
                Method::POST,
                &format!("/v1/memberships/{membership}/assignments"),
                Some(body),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    }
    let service = app.service_token().await;
    World {
        app,
        tenant,
        subject,
        email,
        service,
    }
}

/// A tenant token, and its session id.
async fn sign_in(world: &World, flags: &[&str]) -> (String, String) {
    let login = world
        .app
        .post(
            "/v1/login/password",
            json!({"identifier": world.email, "password": PASSWORD, "flags": flags}),
        )
        .await;
    let auth = format!("Bearer {}", login.body["access_token"].as_str().unwrap());
    let selected = world
        .app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": world.tenant})),
        )
        .await;
    let token = selected.body["access_token"].as_str().unwrap().to_owned();
    let session = world.app.verify(&token).await.sid.to_string();
    (token, session)
}

async fn explain(world: &World, body: Value) -> common::Reply {
    world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/explain-decision", world.subject),
            Some(body),
        )
        .await
}

fn writing_at(id: &str) -> Value {
    json!({"scopes": [{"kind": "project", "id": id, "actions": ["document:write"]}]})
}

// r[verify authz.explain.decision]
// r[verify authz.explain.checks]
#[tokio::test(flavor = "multi_thread")]
async fn decisions_are_explained_policy_by_policy() {
    let world = world().await;
    let explained = explain(
        &world,
        json!({"tenant": world.tenant, "requirements": writing_at("p1")}),
    )
    .await;
    assert_eq!(explained.status, StatusCode::OK, "{:?}", explained.body);
    assert_eq!(explained.body["allowed"], false);
    assert!(
        explained.body.get("decision").is_none(),
        "no session, no decision"
    );
    let action = &explained.body["actions"][0];
    assert_eq!(action["reason"]["kind"], "denied");
    let message = action["message"].as_str().unwrap();
    assert!(
        message.starts_with("Denied: `frozen (")
            && message.contains("denies `document:write` at project/p1 (priority 5)")
            && message.contains("overrides `editor (")
            && message.contains("with a higher priority"),
        "{message}"
    );
    let checks: Vec<&str> = explained.body["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| check["check"].as_str().unwrap())
        .collect();
    assert_eq!(
        checks,
        [
            "subject_active",
            "tenant_active",
            "membership_active",
            "tenant"
        ]
    );

    let read = explain(
        &world,
        json!({"tenant": world.tenant, "requirements": {"tenant": ["document:read"]}}),
    )
    .await;
    assert_eq!(read.body["allowed"], true, "{:?}", read.body);
    assert!(
        read.body["actions"][0]["message"]
            .as_str()
            .unwrap()
            .starts_with("Allowed: `reader (")
    );
    let unknown = explain(
        &world,
        json!({"tenant": world.tenant, "requirements": writing_at("p2")}),
    )
    .await;
    assert_eq!(
        unknown.body["actions"][0]["message"],
        "No policy grants `document:write`."
    );

    // Disabling the subject shows up as a failed check.
    world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/disable", world.subject),
            None,
        )
        .await;
    let disabled = explain(
        &world,
        json!({"tenant": world.tenant, "requirements": {"tenant": ["document:read"]}}),
    )
    .await;
    assert_eq!(disabled.body["allowed"], false);
    assert_eq!(disabled.body["checks"][0]["check"], "subject_active");
    assert_eq!(disabled.body["checks"][0]["passed"], false);
}

// r[verify authz.explain.agreement]
// r[verify authz.explain.checks]
#[tokio::test(flavor = "multi_thread")]
async fn explanations_for_a_session_agree_with_the_check_api() {
    let world = world().await;
    let (token, session) = sign_in(&world, &["personal_only"]).await;
    let auth = format!("Bearer {}", world.service);
    for requirements in [
        json!({"tenant": ["document:read"]}),
        json!({"tenant": ["document:read"], "admit_flags": ["personal_only"]}),
        json!({"tenant": ["document:read"], "admit_flags": ["personal_only"], "step_up": {"min_methods": 2}}),
        writing_at("p1"),
    ] {
        let checked = world
            .app
            .send(
                Method::POST,
                "/v1/check",
                &[("authorization", &auth)],
                Some(json!({"token": token, "requirements": requirements})),
            )
            .await;
        let explained = explain(
            &world,
            json!({"session": session, "requirements": requirements}),
        )
        .await;
        assert_eq!(explained.status, StatusCode::OK, "{:?}", explained.body);
        assert_eq!(
            explained.body["decision"]["decision"], checked.body["decision"],
            "{requirements}: {:?}",
            explained.body
        );
        assert_eq!(
            explained.body["allowed"],
            json!(checked.body["decision"] == "allow"),
            "{requirements}"
        );
    }
    let flagged = explain(
        &world,
        json!({"session": session, "requirements": {"tenant": ["document:read"]}}),
    )
    .await;
    let restricted = flagged.body["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["check"] == "restrictive_flags")
        .unwrap();
    assert_eq!(restricted["passed"], false);
    assert!(
        restricted["message"]
            .as_str()
            .unwrap()
            .contains("`personal_only`")
    );

    // A session of someone else is refused.
    let other = world.app.human("other@example.com", PASSWORD).await;
    let refused = world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{other}/explain-decision"),
            Some(json!({"session": session, "requirements": {}})),
        )
        .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
}
