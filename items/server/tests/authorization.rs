#![allow(clippy::too_many_lines)]

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use konklav_token::TokenKind;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

fn catalog() -> Value {
    json!({
        "actions": [
            {"name": "project:read"},
            {"name": "document:write"},
            {"name": "document:read"},
            {"name": "me"},
            {"name": "sys:user:list"}
        ],
        "groups": [
            {"name": "tenant:all", "all_except_prefixes": ["sys:"]},
            {"name": "sys:all", "all_except_prefixes": []}
        ],
        "scope_kinds": [{"name": "project"}],
        "facts": [
            {"key": "tenant_type", "target": "tenant", "type": "string", "portable": true},
            {"key": "billing_id", "target": "tenant", "type": "string"},
            {"key": "member_number", "target": "membership", "type": "string", "portable": true}
        ],
        "session_flags": [
            {"name": "personal_only", "kind": "restrictive", "requestable": true},
            {"name": "device_bound", "kind": "assertive"}
        ]
    })
}

struct World {
    app: TestApp,
    subject: String,
    tenant: String,
    membership: String,
    email: String,
    service: String,
}

/// A catalog, a `reader` template, a tenant with a role from it, and a
/// human member holding that role at project `p1`.
async fn world() -> World {
    let app = TestApp::new().await;
    let reply = app
        .control(Method::PUT, "/v1/catalog", Some(catalog()))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    app.control(
        Method::PUT,
        "/v1/templates/reader",
        Some(json!({"policies": [
            {"action": "project:read", "effect": "allow"},
            {"action": "document:read", "effect": "allow", "scope_bound": true}
        ]})),
    )
    .await;
    let tenant = uuid::Uuid::now_v7().to_string();
    let created = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({"facts": {"tenant_type": "client", "billing_id": "b-1"}, "templates": ["reader"]})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert!(created.body["cursor"].is_i64());

    let email = format!("{}@example.com", uuid::Uuid::now_v7().simple());
    let subject = app.human(&email, PASSWORD).await;
    let membership = uuid::Uuid::now_v7().to_string();
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": subject, "tenant": tenant, "facts": {"member_number": "m-9"}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    let reply = app
        .control(
            Method::POST,
            &format!("/v1/memberships/{membership}/assignments"),
            Some(json!({"role": "reader", "scope": {"kind": "project", "id": "p1"}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    let service = app.service_token().await;
    World {
        app,
        subject: subject.clone(),
        tenant,
        membership,
        email,
        service,
    }
}

async fn tenant_token(world: &World, flags: &[&str]) -> String {
    let login = world
        .app
        .post(
            "/v1/login/password",
            json!({"identifier": world.email, "password": PASSWORD, "flags": flags}),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let identity = login.body["access_token"].as_str().unwrap().to_owned();
    let auth = format!("Bearer {identity}");
    let selected = world
        .app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": world.tenant})),
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    selected.body["access_token"].as_str().unwrap().to_owned()
}

async fn check(world: &World, token: &str, requirements: Value) -> Value {
    let auth = format!("Bearer {}", world.service);
    let reply = world
        .app
        .send(
            Method::POST,
            "/v1/check",
            &[("authorization", &auth)],
            Some(json!({"token": token, "requirements": requirements})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    reply.body
}

// r[verify authn.login.tenant-selection]
// r[verify authn.login.single-tenant-context]
// r[verify token.access.tenant-claims]
// r[verify token.access.facts]
// r[verify fact.portability]
#[tokio::test(flavor = "multi_thread")]
async fn selecting_a_tenant_issues_a_tenant_token_with_portable_facts() {
    let world = world().await;
    let login = world.app.login(&world.email, PASSWORD).await;
    let identity = login.body["access_token"].as_str().unwrap().to_owned();
    let auth = format!("Bearer {identity}");
    let selected = world
        .app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": world.tenant})),
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    let claims = world
        .app
        .verify(selected.body["access_token"].as_str().unwrap())
        .await;
    assert_eq!(claims.knd, TokenKind::Tenant);
    assert_eq!(claims.tid.unwrap().to_string(), world.tenant);
    assert_eq!(claims.mid.unwrap().to_string(), world.membership);
    assert_eq!(claims.fct.get("tenant_type"), Some(&json!("client")));
    assert_eq!(claims.fct.get("member_number"), Some(&json!("m-9")));
    assert!(
        !claims.fct.contains_key("billing_id"),
        "non-portable facts stay out of tokens"
    );

    // The identity token is superseded by the switch.
    let stale = world
        .app
        .with_bearer(Method::POST, "/v1/sign-out/others", &identity)
        .await;
    assert_eq!(stale.code(), "SESSION_ENDED");
}

#[tokio::test(flavor = "multi_thread")]
async fn tenants_without_an_active_membership_cannot_be_selected() {
    let world = world().await;
    let other = uuid::Uuid::now_v7().to_string();
    world
        .app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{other}"),
            Some(json!({})),
        )
        .await;
    let login = world.app.login(&world.email, PASSWORD).await;
    let auth = format!("Bearer {}", login.body["access_token"].as_str().unwrap());
    let reply = world
        .app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": other})),
        )
        .await;
    assert_eq!(reply.code(), "FORBIDDEN");
}

// r[verify authz.api.entitlements]
// r[verify session.flags.catalog]
// r[verify authz.role.instantiate]
// r[verify tenant.authority]
#[tokio::test(flavor = "multi_thread")]
async fn relying_systems_read_entitlement_sets() {
    let world = world().await;
    let detail = world
        .app
        .control(
            Method::GET,
            &format!("/v1/memberships/{}", world.membership),
            None,
        )
        .await;
    let subject = detail.body["subject_id"].as_str().unwrap().to_owned();
    let uri = format!("/v1/entitlements/{subject}/{}", world.tenant);

    let auth = format!("Bearer {}", world.service);
    let set = world
        .app
        .send(Method::GET, &uri, &[("authorization", &auth)], None)
        .await;
    assert_eq!(set.status, StatusCode::OK, "{:?}", set.body);
    assert_eq!(set.body["tenant"], json!(["project:read"]));
    assert_eq!(
        set.body["scoped"],
        json!([{"kind": "project", "id": "p1", "actions": ["document:read"]}])
    );
    assert_eq!(set.body["restrictive_flags"], json!(["personal_only"]));
    assert!(set.body["revision"].is_i64());

    // Humans can't read other subjects' entitlements.
    let human = tenant_token(&world, &[]).await;
    let forbidden = world.app.with_bearer(Method::GET, &uri, &human).await;
    assert_eq!(forbidden.code(), "FORBIDDEN");
    let anonymous = world.app.send(Method::GET, &uri, &[], None).await;
    assert_eq!(anonymous.code(), "UNAUTHENTICATED");
}

// r[verify authz.api.check]
#[tokio::test(flavor = "multi_thread")]
async fn the_check_api_decides_from_current_state() {
    let world = world().await;
    let token = tenant_token(&world, &[]).await;
    let at_p1 = json!({"scopes": [{"kind": "project", "id": "p1", "actions": ["document:read", "project:read"]}]});
    assert_eq!(
        check(&world, &token, at_p1.clone()).await["decision"],
        "allow"
    );
    let at_p2 = json!({"scopes": [{"kind": "project", "id": "p2", "actions": ["document:read"]}]});
    let denied = check(&world, &token, at_p2).await;
    assert_eq!(denied["decision"], "deny");
    assert_eq!(
        denied["reason"],
        json!({"missing_actions": {"actions": ["document:read"]}})
    );

    // Removing the assignment is visible to the very next check.
    let detail = world
        .app
        .control(
            Method::GET,
            &format!("/v1/memberships/{}", world.membership),
            None,
        )
        .await;
    let assignment = detail.body["assignments"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let removed = world
        .app
        .control(
            Method::DELETE,
            &format!("/v1/assignments/{assignment}"),
            None,
        )
        .await;
    assert_eq!(removed.body["deleted"], true);
    assert!(removed.body["cursor"].is_i64());
    assert_eq!(check(&world, &token, at_p1).await["decision"], "deny");

    let garbage = check(&world, "not.a.token", json!({})).await;
    assert_eq!(
        garbage,
        json!({"decision": "deny", "reason": "invalid_token", "revision": null})
    );
}

// r[verify session.flags.origin]
// r[verify token.access.flags]
#[tokio::test(flavor = "multi_thread")]
async fn requested_restrictive_flags_restrict_the_session() {
    let world = world().await;
    let restricted = tenant_token(&world, &["personal_only"]).await;
    assert_eq!(
        world.app.verify(&restricted).await.sfl,
        vec!["personal_only"]
    );
    let requirements = json!({"tenant": ["project:read"]});
    let denied = check(&world, &restricted, requirements.clone()).await;
    assert_eq!(
        denied["reason"],
        json!({"restricted_session": {"flag": "personal_only"}})
    );
    let admitted = json!({"tenant": ["project:read"], "admit_flags": ["personal_only"]});
    assert_eq!(
        check(&world, &restricted, admitted).await["decision"],
        "allow"
    );

    for flag in ["device_bound", "unknown"] {
        let login = world
            .app
            .post(
                "/v1/login/password",
                json!({"identifier": world.email, "password": PASSWORD, "flags": [flag]}),
            )
            .await;
        assert_eq!(
            login.code(),
            "INVALID_REQUEST",
            "{flag} must not be requestable"
        );
    }
}

// r[verify session.flags.credential]
#[tokio::test(flavor = "multi_thread")]
async fn a_credentials_flags_restrict_every_session_started_with_it() {
    let world = world().await;
    let identifier = format!("{}@flagged.example", uuid::Uuid::now_v7().simple());
    let created = world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/credentials", world.subject),
            Some(json!({"kind": "password", "identifier": identifier, "password": PASSWORD})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let credential = created.body["credential"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/v1/credentials/{credential}/session-flags");
    let set = world
        .app
        .control(
            Method::PUT,
            &path,
            Some(json!({"session_flags": ["personal_only"]})),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{:?}", set.body);
    assert_eq!(set.body["session_flags"], json!(["personal_only"]));

    let login = world
        .app
        .post(
            "/v1/login/password",
            json!({"identifier": identifier, "password": PASSWORD}),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let token = login.body["access_token"].as_str().unwrap();
    assert_eq!(world.app.verify(token).await.sfl, vec!["personal_only"]);
    let other = tenant_token(&world, &[]).await;
    assert!(
        world.app.verify(&other).await.sfl.is_empty(),
        "the person's other credentials are unaffected"
    );

    for flag in ["device_bound", "unknown"] {
        let refused = world
            .app
            .control(Method::PUT, &path, Some(json!({"session_flags": [flag]})))
            .await;
        assert_eq!(
            refused.code(),
            "INVALID_REQUEST",
            "{flag} must not be settable"
        );
    }
}

// r[verify tenant.lifecycle.suspend-revokes]
// r[verify tenant.lifecycle.states]
#[tokio::test(flavor = "multi_thread")]
async fn suspending_a_tenant_ends_its_sessions() {
    let world = world().await;
    let token = tenant_token(&world, &[]).await;
    let suspended = world
        .app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{}/state", world.tenant),
            Some(json!({"state": "suspended"})),
        )
        .await;
    assert_eq!(suspended.body["state"], "suspended");
    let stale = world
        .app
        .with_bearer(Method::POST, "/v1/sign-out/others", &token)
        .await;
    assert_eq!(stale.code(), "SESSION_ENDED");
}

// r[verify membership.state]
#[tokio::test(flavor = "multi_thread")]
async fn ending_a_membership_ends_its_sessions_and_entitlements() {
    let world = world().await;
    let token = tenant_token(&world, &[]).await;
    let ended = world
        .app
        .control(
            Method::POST,
            &format!("/v1/memberships/{}/end", world.membership),
            None,
        )
        .await;
    assert_eq!(ended.body["state"], "ended");
    let stale = world
        .app
        .with_bearer(Method::POST, "/v1/sign-out/others", &token)
        .await;
    assert_eq!(stale.code(), "SESSION_ENDED");
    let subject = ended.body["subject_id"].as_str().unwrap();
    let entitlements = world
        .app
        .control(
            Method::GET,
            &format!(
                "/v1/subjects/{subject}/entitlements?tenant={}",
                world.tenant
            ),
            None,
        )
        .await;
    assert_eq!(
        entitlements.body,
        json!({"global": [], "tenant": [], "scoped": []})
    );
}

// r[verify fact.typed]
// r[verify fact.bounded]
#[tokio::test(flavor = "multi_thread")]
async fn facts_must_match_the_catalog() {
    let world = world().await;
    let uri = format!("/v1/tenants/{}/facts", world.tenant);
    for facts in [
        json!({"undeclared": 1}),
        json!({"tenant_type": 7}),
        json!({"tenant_type": "x".repeat(2000)}),
    ] {
        let reply = world
            .app
            .control(Method::PUT, &uri, Some(facts.clone()))
            .await;
        assert_eq!(reply.code(), "INVALID_REQUEST", "{facts}");
    }
    let ok = world
        .app
        .control(Method::PUT, &uri, Some(json!({"tenant_type": "personal"})))
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
}

// r[verify authz.assignment.capabilities]
// r[verify authz.assignment.multiple]
// r[verify authz.role.priority]
#[tokio::test(flavor = "multi_thread")]
async fn global_roles_grant_in_every_tenant() {
    let world = world().await;
    world
        .app
        .control(
            Method::PUT,
            "/v1/tenants/root/roles/ROOT",
            Some(json!({"policies": [{"action": "sys:all", "effect": "allow"}]})),
        )
        .await;
    let detail = world
        .app
        .control(
            Method::GET,
            &format!("/v1/memberships/{}", world.membership),
            None,
        )
        .await;
    let subject = detail.body["subject_id"].as_str().unwrap().to_owned();
    let assigned = world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": "ROOT"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    let tenant_role = world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": "reader"})),
        )
        .await;
    assert_eq!(
        tenant_role.code(),
        "NOT_FOUND",
        "tenant roles aren't global"
    );

    let token = tenant_token(&world, &[]).await;
    let requirements = json!({"global": ["sys:all", "sys:user:list"]});
    assert_eq!(
        check(&world, &token, requirements).await["decision"],
        "allow"
    );
}

// r[verify fact.unique-keys]
#[tokio::test(flavor = "multi_thread")]
async fn catalog_documents_are_validated() {
    let world = world().await;
    let mut assertive_requestable = catalog();
    assertive_requestable["session_flags"][1]["requestable"] = json!(true);
    let reply = world
        .app
        .control(Method::PUT, "/v1/catalog", Some(assertive_requestable))
        .await;
    assert_eq!(reply.code(), "INVALID_REQUEST");

    let mut duplicate_fact = catalog();
    duplicate_fact["facts"]
        .as_array_mut()
        .unwrap()
        .push(json!({"key": "tenant_type", "target": "membership", "type": "string"}));
    let reply = world
        .app
        .control(Method::PUT, "/v1/catalog", Some(duplicate_fact))
        .await;
    assert_eq!(
        reply.code(),
        "INVALID_REQUEST",
        "fact keys are unique across targets"
    );

    let mut without_read = catalog();
    without_read["actions"].as_array_mut().unwrap().remove(0);
    let reply = world
        .app
        .control(Method::PUT, "/v1/catalog", Some(without_read))
        .await;
    assert_eq!(
        reply.code(),
        "CONFLICT",
        "project:read is used by a template"
    );
}

// r[verify authz.api.check-equivalence]
// r[verify item.authz.single-evaluator]
#[tokio::test(flavor = "multi_thread")]
async fn local_evaluation_matches_the_check_api() {
    let world = world().await;
    let token = tenant_token(&world, &["personal_only"]).await;
    let claims = world.app.verify(&token).await;
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
    let restrictive: std::collections::BTreeSet<String> =
        serde_json::from_value(set["restrictive_flags"].clone()).unwrap();

    let cases = [
        json!({"tenant": ["project:read"]}),
        json!({"tenant": ["project:read"], "admit_flags": ["personal_only"]}),
        json!({"scopes": [{"kind": "project", "id": "p1", "actions": ["document:read"]}], "admit_flags": ["personal_only"]}),
        json!({"global": ["me"], "admit_flags": ["personal_only"]}),
        json!({"require_flags": ["device_bound"], "admit_flags": ["personal_only"]}),
        json!({"step_up": {"min_methods": 2}, "admit_flags": ["personal_only"]}),
    ];
    for requirements in cases {
        let parsed: konklav_authz::Requirements =
            serde_json::from_value(requirements.clone()).unwrap();
        let local = konklav_authz::evaluate(
            &parsed,
            &claims,
            &restrictive,
            &entitlements,
            &konklav_authz::RegisteredScopes::default(),
            chrono::Utc::now().timestamp(),
        );
        let mut central = check(&world, &token, requirements.clone()).await;
        central.as_object_mut().unwrap().remove("revision");
        assert_eq!(
            serde_json::to_value(&local).unwrap(),
            central,
            "{requirements}"
        );
    }
}
