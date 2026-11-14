#![allow(clippy::too_many_lines)]

//! Vouches: `user:manage_data` vouches for `user:write`, from the catalog
//! through route authority.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use serde_json::{Value, json};

fn catalog() -> Value {
    json!({
        "actions": [
            {"name": "user:manage_data", "vouches": ["user:write", "user:data"]},
            {"name": "user:write"},
            {"name": "user:read"},
            {"name": "user:export"}
        ],
        "groups": [
            {"name": "user:data", "actions": ["user:read", "user:export"]}
        ],
        "scope_kinds": [{"name": "project"}, {"name": "document", "registered": true}]
    })
}

const PASSWORD: &str = "correct horse battery";

async fn app() -> TestApp {
    let app = TestApp::new().await;
    let reply = app
        .control(Method::PUT, "/v1/catalog", Some(catalog()))
        .await;
    assert!(
        reply.status.is_success(),
        "{} {:?}",
        reply.status,
        reply.body
    );
    app
}

// r[verify authz.catalog.vouches]
#[tokio::test(flavor = "multi_thread")]
async fn the_catalog_keeps_vouches() {
    let app = app().await;
    let read = app.control(Method::GET, "/v1/catalog", None).await;
    assert_eq!(read.status, StatusCode::OK, "{:?}", read.body);
    let actions = read.body["actions"].as_array().unwrap();
    let entry = |name: &str| actions.iter().find(|a| a["name"] == name).unwrap();
    assert_eq!(
        entry("user:manage_data")["vouches"],
        json!(["user:data", "user:write"])
    );
    assert!(entry("user:write").get("vouches").is_none(), "{actions:?}");
}

// r[verify authz.catalog.vouches]
// r[verify authz.catalog.removal]
#[tokio::test(flavor = "multi_thread")]
async fn catalogs_with_unsound_vouches_are_refused() {
    let app = app().await;
    let vouching = |vouches: Value| {
        let mut document = catalog();
        document["actions"][0]["vouches"] = vouches;
        document
    };
    let without_write = {
        let mut document = catalog();
        document["actions"]
            .as_array_mut()
            .unwrap()
            .retain(|a| a["name"] != "user:write");
        document
    };
    let cases = [
        ("itself", vouching(json!(["user:manage_data"]))),
        ("an undeclared action", vouching(json!(["user:delete"]))),
        ("a capability", vouching(json!(["konklav:tenant:create"]))),
        ("a vouched action removed", without_write),
    ];
    for (case, document) in cases {
        let reply = app
            .control(Method::PUT, "/v1/catalog", Some(document))
            .await;
        assert!(
            reply.status.is_client_error(),
            "{case}: {} {:?}",
            reply.status,
            reply.body
        );
    }
    let read = app.control(Method::GET, "/v1/catalog", None).await;
    let manage_data = read.body["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "user:manage_data")
        .unwrap();
    assert_eq!(
        manage_data["vouches"],
        json!(["user:data", "user:write"]),
        "nothing changed"
    );
}

struct World {
    app: TestApp,
    tenant: String,
    token: String,
    service: String,
    subject: String,
}

/// A member of a tenant holding `user:manage_data` tenant-wide and at
/// project p-1, with `user:write` explicitly denied, and documents d-1 in
/// p-1 and d-2 in p-2.
async fn world() -> World {
    let app = app().await;
    let reply = app
        .control(
            Method::PUT,
            "/v1/templates/steward",
            Some(json!({"policies": [
                {"action": "user:manage_data", "effect": "allow"},
                {"action": "user:write", "effect": "deny"}
            ]})),
        )
        .await;
    assert!(reply.status.is_success(), "{:?}", reply.body);
    let tenant = uuid::Uuid::now_v7().to_string();
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({"templates": ["steward"]})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
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
    let reply = app
        .control(
            Method::POST,
            &format!("/v1/memberships/{membership}/assignments"),
            Some(json!({"role": "steward"})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    for (id, project) in [("d-1", "p-1"), ("d-2", "p-2")] {
        let reply = app
            .control(
                Method::PUT,
                &format!("/v1/registered-scopes/document/{id}"),
                Some(json!({"tenant": tenant, "containers": [{"kind": "project", "id": project}]})),
            )
            .await;
        assert!(reply.status.is_success(), "{:?}", reply.body);
    }

    let login = app.login(&email, PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let identity = login.body["access_token"].as_str().unwrap().to_owned();
    let auth = format!("Bearer {identity}");
    let selected = app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": tenant})),
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    let token = selected.body["access_token"].as_str().unwrap().to_owned();
    let service = app.service_token().await;
    World {
        app,
        tenant,
        token,
        service,
        subject: subject.clone(),
    }
}

/// `POST /v1/check`, with `route_authority` when given, without the
/// revision.
async fn check(world: &World, requirements: &Value, route_authority: Option<&Value>) -> Value {
    let auth = format!("Bearer {}", world.service);
    let mut body = json!({"token": world.token, "requirements": requirements});
    if let Some(authority) = route_authority {
        body["route_authority"] = authority.clone();
    }
    let reply = world
        .app
        .send(
            Method::POST,
            "/v1/check",
            &[("authorization", &auth)],
            Some(body),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let mut decision = reply.body;
    decision.as_object_mut().unwrap().remove("revision");
    decision
}

// r[verify authz.api.check-route-authority]
// r[verify authz.decision.vouches]
// r[verify authz.decision.route-authority]
// r[verify authz.decision.route-authority.coverage]
// r[verify authz.compile.vouches]
#[tokio::test(flavor = "multi_thread")]
async fn the_check_api_decides_with_route_authority() {
    let world = world().await;
    let write = json!({"tenant": ["user:write"]});
    assert_eq!(
        check(&world, &write, None).await,
        json!({"decision": "deny", "reason": {"missing_actions": {"actions": ["user:write"]}}}),
        "without route authority, user:write is denied"
    );

    let route = check(&world, &json!({"tenant": ["user:manage_data"]}), None).await;
    let vouched = json!(["user:data", "user:export", "user:read", "user:write"]);
    assert_eq!(
        route,
        json!({"decision": "allow", "vouches": {"tenant": vouched}}),
        "the route decision names what it vouches for"
    );
    let authority = route["vouches"].clone();
    assert_eq!(
        check(&world, &write, Some(&authority)).await,
        json!({"decision": "allow"}),
        "the vouch overrides the deny, and vouches for nothing further"
    );
    let document =
        |id: &str| json!({"scopes": [{"kind": "document", "id": id, "actions": ["user:read"]}]});
    assert_eq!(
        check(&world, &document("d-2"), Some(&authority)).await,
        json!({"decision": "allow"}),
        "tenant-wide route authority covers registered scopes in the tenant"
    );

    let at_p1 = check(
        &world,
        &json!({"scopes": [{"kind": "project", "id": "p-1", "actions": ["user:manage_data"]}]}),
        None,
    )
    .await;
    let p1 = at_p1["vouches"].clone();
    assert_eq!(
        p1,
        json!({"scopes": [{"kind": "project", "id": "p-1", "actions": vouched}]}),
        "{at_p1}"
    );
    assert_eq!(
        check(&world, &document("d-1"), Some(&p1)).await,
        json!({"decision": "allow"}),
        "a project's route authority covers a document recorded in it"
    );
    assert_eq!(
        check(&world, &document("d-2"), Some(&p1)).await,
        json!({"decision": "deny", "reason": {"missing_actions": {"actions": ["user:read"]}}}),
        "but not one in another project"
    );
    assert_eq!(
        check(&world, &write, Some(&p1)).await,
        json!({"decision": "deny", "reason": {"missing_actions": {"actions": ["user:write"]}}}),
        "nor tenant-wide"
    );
    assert_eq!(
        check(&world, &document("d-9"), Some(&p1)).await,
        json!({"decision": "deny", "reason": {"unknown_scope": {"kind": "document", "id": "d-9"}}}),
        "an unknown registered scope still denies"
    );
}

// r[verify authz.api.check-equivalence]
#[tokio::test(flavor = "multi_thread")]
async fn local_evaluation_with_route_authority_matches_the_check_api() {
    let world = world().await;
    let claims = world.app.verify(&world.token).await;
    let auth = format!("Bearer {}", world.service);
    let set = world
        .app
        .send(
            Method::GET,
            &format!("/v1/entitlements/{}/{}", claims.sub, world.tenant),
            &[("authorization", &auth)],
            None,
        )
        .await
        .body;
    let entitlements: konklav_authz::Entitlements = serde_json::from_value(set.clone()).unwrap();
    assert!(!entitlements.vouches.is_empty(), "{set}");

    let p1 = json!({"scopes": [{"kind": "project", "id": "p-1", "actions": ["user:write"]}]});
    let cases = [
        (json!({"tenant": ["user:manage_data"]}), None),
        (json!({"tenant": ["user:write"]}), None),
        (
            json!({"tenant": ["user:write"]}),
            Some(json!({"tenant": ["user:write"]})),
        ),
        (
            json!({"tenant": ["user:write"]}),
            Some(json!({"global": ["user:write"]})),
        ),
        (
            p1.clone(),
            Some(json!({"scopes": [{"kind": "project", "id": "p-2", "actions": ["user:write"]}]})),
        ),
        (p1, Some(json!({}))),
    ];
    for (requirements, authority) in cases {
        let parsed: konklav_authz::Requirements =
            serde_json::from_value(requirements.clone()).unwrap();
        let route_authority: Option<konklav_authz::RouteAuthority> = authority
            .clone()
            .map(|authority| serde_json::from_value(authority).unwrap());
        let local = konklav_authz::evaluate_with_route_authority(
            &parsed,
            route_authority.as_ref(),
            &claims,
            &std::collections::BTreeSet::new(),
            &konklav_authz::Confinements::default(),
            &entitlements,
            &konklav_authz::RegisteredScopes::default(),
            chrono::Utc::now().timestamp(),
        );
        assert_eq!(
            serde_json::to_value(&local).unwrap(),
            check(&world, &requirements, authority.as_ref()).await,
            "{requirements} {authority:?}"
        );
    }
}

// r[verify authz.explain.route-authority]
// r[verify authz.explain.agreement]
#[tokio::test(flavor = "multi_thread")]
async fn explanations_name_the_route_decisions_vouch() {
    let world = world().await;
    let explain = |body: Value| {
        let world = &world;
        async move {
            let reply = world
                .app
                .control(
                    Method::POST,
                    &format!("/v1/subjects/{}/explain-decision", world.subject),
                    Some(body),
                )
                .await;
            assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
            reply.body
        }
    };
    let write = json!({"tenant": ["user:write"]});
    let alone = explain(json!({"tenant": world.tenant, "requirements": write})).await;
    assert_eq!(alone["allowed"], false, "{alone}");
    assert!(alone.get("route").is_none(), "{alone}");

    let routed = explain(json!({
        "tenant": world.tenant,
        "requirements": write,
        "route": {"tenant": ["user:manage_data"]},
    }))
    .await;
    assert_eq!(routed["allowed"], true, "{routed}");
    assert_eq!(routed["route"]["allowed"], true, "{routed}");
    assert_eq!(
        routed["route"]["vouches"],
        json!({"tenant": ["user:data", "user:export", "user:read", "user:write"]})
    );
    let reason = &routed["actions"][0]["reason"];
    assert_eq!(reason["kind"], "vouched", "{routed}");
    assert_eq!(reason["vouching"], "user:manage_data");
    assert_eq!(reason["at"], "tenant");
    assert_eq!(reason["held"]["kind"], "denied", "{routed}");

    // A project's vouch, explained at a document recorded in the project.
    let document =
        |id: &str| json!({"scopes": [{"kind": "document", "id": id, "actions": ["user:read"]}]});
    let route =
        json!({"scopes": [{"kind": "project", "id": "p-1", "actions": ["user:manage_data"]}]});
    let inside = explain(json!({
        "tenant": world.tenant, "requirements": document("d-1"), "route": route,
    }))
    .await;
    assert_eq!(inside["allowed"], true, "{inside}");
    assert_eq!(
        inside["actions"][0]["reason"]["at"], "project/p-1",
        "{inside}"
    );
    let outside = explain(json!({
        "tenant": world.tenant, "requirements": document("d-2"), "route": route,
    }))
    .await;
    assert_eq!(outside["allowed"], false, "{outside}");
}
