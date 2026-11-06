#![allow(clippy::too_many_lines)]

//! Tenant fact requirements: operations only client tenants may use, from
//! the check API through entitlement sets and explanations.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

fn catalog() -> Value {
    json!({
        "actions": [{"name": "tenant:read"}, {"name": "me"}],
        "facts": [
            {"key": "tenant_type", "target": "tenant", "type": "string", "portable": true},
            {"key": "billing_id", "target": "tenant", "type": "string"},
            {"key": "seats", "target": "tenant", "type": "integer", "portable": true},
            {"key": "labels", "target": "tenant", "type": "string_list", "portable": true},
            {"key": "member_type", "target": "membership", "type": "string", "portable": true}
        ]
    })
}

struct World {
    app: TestApp,
    subject: String,
    client: String,
    service: String,
    token: String,
}

/// A member of a client tenant with facts of every kind, reading it and
/// holding `me` globally, with a tenant token for it.
async fn world() -> World {
    let app = TestApp::new().await;
    let reply = app
        .control(Method::PUT, "/v1/catalog", Some(catalog()))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let email = format!("{}@example.com", uuid::Uuid::now_v7().simple());
    let subject = app.human(&email, PASSWORD).await;
    let client = uuid::Uuid::now_v7().to_string();
    let facts = json!({"tenant_type": "client", "billing_id": "b-1", "seats": 5, "labels": ["a"]});
    let created = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{client}"),
            Some(json!({"facts": facts})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let role = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{client}/roles/reader"),
            Some(json!({"policies": [{"action": "tenant:read", "effect": "allow"}]})),
        )
        .await;
    assert!(role.status.is_success(), "{:?}", role.body);
    let membership = uuid::Uuid::now_v7().to_string();
    let joined = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": subject, "tenant": client})),
        )
        .await;
    assert_eq!(joined.status, StatusCode::CREATED, "{:?}", joined.body);
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/memberships/{membership}/assignments"),
            Some(json!({"role": "reader"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    let role = app
        .control(
            Method::PUT,
            "/v1/tenants/root/roles/self",
            Some(json!({"policies": [{"action": "me", "effect": "allow"}]})),
        )
        .await;
    assert!(role.status.is_success(), "{:?}", role.body);
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": "self"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);

    let login = app.login(&email, PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let identity = login.body["access_token"].as_str().unwrap().to_owned();
    let auth = format!("Bearer {identity}");
    let selected = app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": client})),
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    let token = selected.body["access_token"].as_str().unwrap().to_owned();
    let service = app.service_token().await;
    World {
        app,
        subject,
        client,
        service,
        token,
    }
}

async fn check(world: &World, requirements: &Value) -> common::Reply {
    let auth = format!("Bearer {}", world.service);
    world
        .app
        .send(
            Method::POST,
            "/v1/check",
            &[("authorization", &auth)],
            Some(json!({"token": world.token, "requirements": requirements})),
        )
        .await
}

async fn decide(world: &World, requirements: &Value) -> Value {
    let reply = check(world, requirements).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    reply.body
}

// r[verify authz.decision.tenant-facts]
// r[verify authz.decision.tenant-facts.reason]
// r[verify authz.api.check]
#[tokio::test(flavor = "multi_thread")]
async fn the_check_api_decides_tenant_facts_from_current_state() {
    let world = world().await;
    let clients = json!({"tenant": ["tenant:read"], "tenant_facts": {"tenant_type": ["client"], "seats": [5, 10]}});
    assert_eq!(decide(&world, &clients).await["decision"], "allow");

    let personal = json!({"global": ["me"], "tenant_facts": {"tenant_type": ["personal"]}});
    let denied = decide(&world, &personal).await;
    assert_eq!(
        denied["reason"],
        json!({"tenant_facts": {"fact": "tenant_type"}}),
        "global actions don't lift it: {denied:?}"
    );

    // Non-portable facts are never matched.
    let billing = json!({"tenant_facts": {"billing_id": ["b-1"]}});
    assert_eq!(
        decide(&world, &billing).await["reason"],
        json!({"tenant_facts": {"fact": "billing_id"}})
    );

    // The tenant's current facts count, not the token's.
    let reply = world
        .app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{}/facts", world.client),
            Some(json!({"tenant_type": "client", "seats": 20})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(
        decide(&world, &clients).await["reason"],
        json!({"tenant_facts": {"fact": "seats"}})
    );
}

// r[verify authz.decision.tenant-facts.shape]
#[tokio::test(flavor = "multi_thread")]
async fn unmatchable_predicates_are_refused() {
    let world = world().await;
    for predicates in [
        json!({"tenant_type": []}),
        json!({"seats": [1.5]}),
        json!({"labels": [["a"]]}),
    ] {
        let reply = check(&world, &json!({"tenant_facts": predicates})).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{predicates}");
    }
    // An undeclared fact is read, and denies.
    assert_eq!(
        decide(&world, &json!({"tenant_facts": {"undeclared": ["x"]}})).await["reason"],
        json!({"tenant_facts": {"fact": "undeclared"}})
    );
}

// r[verify authz.compile.tenant-facts]
#[tokio::test(flavor = "multi_thread")]
async fn entitlement_sets_carry_every_portable_tenant_fact() {
    let world = world().await;
    let auth = format!("Bearer {}", world.service);
    let set = world
        .app
        .send(
            Method::GET,
            &format!("/v1/entitlements/{}/{}", world.subject, world.client),
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{:?}", set.body);
    assert_eq!(
        set.body["confinements"],
        json!({"tenant_facts": {"tenant_type": "client", "seats": 5, "labels": ["a"]}}),
        "without the non-portable `billing_id`"
    );
    let global = world
        .app
        .send(
            Method::GET,
            &format!("/v1/entitlements/{}", world.subject),
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(global.status, StatusCode::OK, "{:?}", global.body);
    assert_eq!(
        global.body.get("confinements"),
        None,
        "none without a tenant"
    );
}

// r[verify authz.explain.tenant-facts]
// r[verify authz.explain.agreement]
#[tokio::test(flavor = "multi_thread")]
async fn explanations_report_the_tenant_facts_check() {
    let world = world().await;
    let explain = async |tenant: Option<&str>, requirements: Value| {
        let mut body = json!({"requirements": requirements});
        if let Some(tenant) = tenant {
            body["tenant"] = json!(tenant);
        }
        let explained = world
            .app
            .control(
                Method::POST,
                &format!("/v1/subjects/{}/explain-decision", world.subject),
                Some(body),
            )
            .await;
        assert_eq!(explained.status, StatusCode::OK, "{:?}", explained.body);
        explained.body
    };
    let check_of = |explained: &Value| {
        explained["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["check"] == "tenant_facts")
            .cloned()
            .unwrap()
    };

    let personal =
        json!({"tenant": ["tenant:read"], "tenant_facts": {"tenant_type": ["personal"]}});
    let denied = explain(Some(&world.client), personal.clone()).await;
    assert_eq!(denied["allowed"], false);
    let check = check_of(&denied);
    assert_eq!(check["passed"], false);
    assert_eq!(
        check["message"],
        "The operation needs a tenant where `tenant_type` is one of `\"personal\"`; the \
         tenant fails on `tenant_type` (`tenant_type` is `\"client\"`)."
    );

    let clients = json!({"tenant": ["tenant:read"], "tenant_facts": {"tenant_type": ["client"]}});
    let allowed = explain(Some(&world.client), clients).await;
    assert_eq!(allowed["allowed"], true, "{allowed:?}");
    assert_eq!(check_of(&allowed)["passed"], true);

    let nowhere = explain(None, json!({"tenant_facts": {"tenant_type": ["client"]}})).await;
    assert_eq!(nowhere["allowed"], false);
    assert_eq!(check_of(&nowhere)["passed"], false);
}
