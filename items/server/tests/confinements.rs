#![allow(clippy::too_many_lines)]

//! Confinements: `personal_only` confined to personal tenants, from the
//! catalog through tenant selection, issuance, decisions and explanations.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

fn catalog() -> Value {
    json!({
        "actions": [{"name": "patient:read"}, {"name": "me"}],
        "facts": [
            {"key": "tenant_type", "target": "tenant", "type": "string", "portable": true},
            {"key": "billing_id", "target": "tenant", "type": "string"},
            {"key": "seats", "target": "tenant", "type": "integer", "portable": true},
            {"key": "labels", "target": "tenant", "type": "string_list", "portable": true},
            {"key": "member_type", "target": "membership", "type": "string", "portable": true}
        ],
        "session_flags": [
            {"name": "personal_only", "kind": "restrictive", "requestable": true,
             "confine": {"tenant": {"tenant_type": ["personal"]}}},
            {"name": "device_bound", "kind": "assertive"}
        ]
    })
}

struct World {
    app: TestApp,
    email: String,
    subject: String,
    personal: String,
    client: String,
    service: String,
}

/// A member of a personal and a client tenant, reading patients in both and
/// holding `me` globally.
async fn world() -> World {
    let app = TestApp::new().await;
    let reply = app
        .control(Method::PUT, "/v1/catalog", Some(catalog()))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let email = format!("{}@example.com", uuid::Uuid::now_v7().simple());
    let subject = app.human(&email, PASSWORD).await;
    let mut tenants = Vec::new();
    for tenant_type in ["personal", "client"] {
        let tenant = uuid::Uuid::now_v7().to_string();
        let created = app
            .control(
                Method::PUT,
                &format!("/v1/tenants/{tenant}"),
                Some(json!({"facts": {"tenant_type": tenant_type}})),
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
        let role = app
            .control(
                Method::PUT,
                &format!("/v1/tenants/{tenant}/roles/carer"),
                Some(json!({"policies": [{"action": "patient:read", "effect": "allow"}]})),
            )
            .await;
        assert!(role.status.is_success(), "{:?}", role.body);
        let membership = uuid::Uuid::now_v7().to_string();
        let joined = app
            .control(
                Method::PUT,
                &format!("/v1/memberships/{membership}"),
                Some(json!({"subject": subject, "tenant": tenant})),
            )
            .await;
        assert_eq!(joined.status, StatusCode::CREATED, "{:?}", joined.body);
        let assigned = app
            .control(
                Method::POST,
                &format!("/v1/memberships/{membership}/assignments"),
                Some(json!({"role": "carer"})),
            )
            .await;
        assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
        tenants.push(tenant);
    }
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
    let service = app.service_token().await;
    let client = tenants.pop().unwrap();
    let personal = tenants.pop().unwrap();
    World {
        app,
        email,
        subject,
        personal,
        client,
        service,
    }
}

/// A login's identity token and refresh token.
async fn login(world: &World, flags: &[&str]) -> (String, String) {
    let login = world
        .app
        .post(
            "/v1/login/password",
            json!({"identifier": world.email, "password": PASSWORD, "flags": flags}),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    (
        login.body["access_token"].as_str().unwrap().to_owned(),
        login.body["refresh_token"].as_str().unwrap().to_owned(),
    )
}

async fn select(world: &World, identity: &str, tenant: &str) -> common::Reply {
    let auth = format!("Bearer {identity}");
    world
        .app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": tenant})),
        )
        .await
}

async fn check(world: &World, token: &str, requirements: &Value) -> Value {
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

async fn set_tenant_type(world: &World, tenant: &str, tenant_type: &str) {
    let reply = world
        .app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}/facts"),
            Some(json!({"tenant_type": tenant_type})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
}

fn admitting(requirements: Value) -> Value {
    let mut requirements = requirements;
    requirements["admit_flags"] = json!(["personal_only"]);
    requirements
}

fn confined() -> Value {
    json!({"confined_session": {"flag": "personal_only"}})
}

// r[verify authz.catalog.flag-confinement]
// r[verify session.flags.confine]
#[tokio::test(flavor = "multi_thread")]
async fn the_catalog_keeps_confinements() {
    let world = world().await;
    let read = world.app.control(Method::GET, "/v1/catalog", None).await;
    assert_eq!(read.status, StatusCode::OK, "{:?}", read.body);
    let flags = read.body["session_flags"].as_array().unwrap();
    let personal_only = flags
        .iter()
        .find(|flag| flag["name"] == "personal_only")
        .unwrap();
    assert_eq!(
        personal_only["confine"],
        json!({"tenant": {"tenant_type": ["personal"]}})
    );
    let device_bound = flags
        .iter()
        .find(|flag| flag["name"] == "device_bound")
        .unwrap();
    assert!(device_bound.get("confine").is_none(), "{device_bound}");
}

// r[verify session.flags.confine.facts]
// r[verify authz.catalog.flag-confinement]
#[tokio::test(flavor = "multi_thread")]
async fn catalogs_with_unsound_confinements_are_refused() {
    let world = world().await;
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut document = catalog();
        edit(&mut document);
        document
    };
    let confine = |confinement: Value| {
        move |document: &mut Value| document["session_flags"][0]["confine"] = confinement.clone()
    };
    let cases: Vec<(&str, Value)> = vec![
        (
            "an assertive flag",
            with(&|document| {
                document["session_flags"][1]["confine"] =
                    json!({"tenant": {"tenant_type": ["personal"]}});
            }),
        ),
        ("no predicate", with(&confine(json!({"tenant": {}})))),
        (
            "no value",
            with(&confine(json!({"tenant": {"tenant_type": []}}))),
        ),
        (
            "an undeclared fact",
            with(&confine(json!({"tenant": {"kind": ["personal"]}}))),
        ),
        (
            "a membership fact",
            with(&confine(json!({"tenant": {"member_type": ["owner"]}}))),
        ),
        (
            "a non-portable fact",
            with(&confine(json!({"tenant": {"billing_id": ["b-1"]}}))),
        ),
        (
            "a string list",
            with(&confine(json!({"tenant": {"labels": ["a"]}}))),
        ),
        (
            "a value of the wrong type",
            with(&confine(json!({"tenant": {"seats": ["10"]}}))),
        ),
        (
            "the fact made non-portable",
            with(&|document| document["facts"][0]["portable"] = json!(false)),
        ),
        (
            "the fact removed",
            with(&|document| {
                document["facts"].as_array_mut().unwrap().remove(0);
            }),
        ),
    ];
    for (case, document) in cases {
        let reply = world
            .app
            .control(Method::PUT, "/v1/catalog", Some(document))
            .await;
        assert!(
            reply.status.is_client_error(),
            "{case}: {} {:?}",
            reply.status,
            reply.body
        );
    }
    let unknown = world
        .app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(with(&confine(
                json!({"tenant": {"tenant_type": ["personal"]}, "membership": {}}),
            ))),
        )
        .await;
    assert_eq!(
        unknown.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        unknown.body
    );

    // Integer and boolean facts can be matched.
    let accepted = world
        .app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(with(&confine(
                json!({"tenant": {"tenant_type": ["personal"], "seats": [1, 2]}}),
            ))),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
}

// r[verify session.flags.confine.tenant]
#[tokio::test(flavor = "multi_thread")]
async fn a_confined_session_enters_only_matching_tenants() {
    let world = world().await;
    let (identity, _) = login(&world, &["personal_only"]).await;
    let refused = select(&world, &identity, &world.client).await;
    assert_eq!(refused.code(), "FORBIDDEN", "{:?}", refused.body);
    assert!(
        refused.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("`personal_only`"),
        "{:?}",
        refused.body
    );
    // Refusing left the session where it was.
    let selected = select(&world, &identity, &world.personal).await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);

    // Without the flag, either tenant can be entered.
    let (identity, _) = login(&world, &[]).await;
    let selected = select(&world, &identity, &world.client).await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
}

// r[verify session.flags.confine.tenant]
// r[verify session.flags.confine.decision]
// r[verify session.flags.confine.invalidate]
#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_that_stops_matching_denies_and_issues_nothing() {
    let world = world().await;
    let (identity, refresh) = login(&world, &["personal_only"]).await;
    let selected = select(&world, &identity, &world.personal).await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    let token = selected.body["access_token"].as_str().unwrap().to_owned();
    let reading = admitting(json!({"tenant": ["patient:read"]}));
    assert_eq!(check(&world, &token, &reading).await["decision"], "allow");

    let auth = format!("Bearer {}", world.service);
    let before = world
        .app
        .send(
            Method::GET,
            "/v1/events/batch?after=0&kinds=entitlements.changed&limit=1000",
            &[("authorization", &auth)],
            None,
        )
        .await;
    let seen = before.body["events"].as_array().unwrap().len();

    set_tenant_type(&world, &world.personal, "client").await;

    // The change invalidates every entitlement set for the tenant.
    let after = world
        .app
        .send(
            Method::GET,
            "/v1/events/batch?after=0&kinds=entitlements.changed&limit=1000",
            &[("authorization", &auth)],
            None,
        )
        .await;
    let events = after.body["events"].as_array().unwrap();
    assert_eq!(events.len(), seen + 1, "{:?}", after.body);
    let payload = &events.last().unwrap()["payload"];
    assert_eq!(payload["all"], true);
    assert_eq!(payload["tenant"], json!(world.personal));

    // The token still verifies, but decisions deny, global actions too.
    let denied = check(&world, &token, &reading).await;
    assert_eq!(denied["reason"], confined(), "{denied:?}");
    let global = admitting(json!({"global": ["me"]}));
    assert_eq!(check(&world, &token, &global).await["reason"], confined());

    // The entitlement set carries what the relying core needs.
    let set = world
        .app
        .send(
            Method::GET,
            &format!("/v1/entitlements/{}/{}", world.subject, world.personal),
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(
        set.body["confinements"],
        json!({
            "flags": {"personal_only": {"tenant": {"tenant_type": ["personal"]}}},
            "tenant_facts": {"tenant_type": "client"},
        })
    );

    // And no new tenant token is issued for the session.
    let refreshed = world
        .app
        .post("/v1/refresh", json!({"refresh_token": refresh}))
        .await;
    assert_eq!(refreshed.code(), "FORBIDDEN", "{:?}", refreshed.body);

    // Matching again, the session acts and refreshes again: the refused
    // refresh rotated nothing.
    set_tenant_type(&world, &world.personal, "personal").await;
    assert_eq!(check(&world, &token, &reading).await["decision"], "allow");
    let refreshed = world
        .app
        .post("/v1/refresh", json!({"refresh_token": refresh}))
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
}

// r[verify session.flags.confine.decision]
#[tokio::test(flavor = "multi_thread")]
async fn a_confined_session_without_a_tenant_acts_nowhere() {
    let world = world().await;
    let (identity, _) = login(&world, &["personal_only"]).await;
    let global = admitting(json!({"token_kinds": ["identity"], "global": ["me"]}));
    assert_eq!(
        check(&world, &identity, &global).await["reason"],
        confined()
    );

    let (identity, _) = login(&world, &[]).await;
    assert_eq!(
        check(&world, &identity, &global).await["decision"],
        "allow",
        "unconfined sessions hold their global actions without a tenant"
    );
}

// r[verify authz.explain.confinement]
// r[verify authz.explain.agreement]
#[tokio::test(flavor = "multi_thread")]
async fn explanations_name_the_confinement() {
    let world = world().await;
    let (identity, _) = login(&world, &["personal_only"]).await;
    let selected = select(&world, &identity, &world.personal).await;
    let token = selected.body["access_token"].as_str().unwrap().to_owned();
    let session = world.app.verify(&token).await.sid.to_string();
    set_tenant_type(&world, &world.personal, "client").await;

    let reading = admitting(json!({"tenant": ["patient:read"]}));
    let explained = world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/explain-decision", world.subject),
            Some(json!({"session": session, "requirements": reading})),
        )
        .await;
    assert_eq!(explained.status, StatusCode::OK, "{:?}", explained.body);
    assert_eq!(explained.body["allowed"], false);
    assert_eq!(
        explained.body["decision"],
        json!({"decision": "deny", "reason": confined()})
    );
    let checks = explained.body["checks"].as_array().unwrap();
    let confinement = checks
        .iter()
        .find(|check| check["check"] == "confinement")
        .unwrap();
    assert_eq!(confinement["passed"], false);
    assert_eq!(
        confinement["message"],
        "`personal_only` confines the session to tenants where `tenant_type` is one of \
         `\"personal\"`; the tenant fails on `tenant_type` (`tenant_type` is `\"client\"`)."
    );
    let failing: Vec<&Value> = checks
        .iter()
        .filter(|check| check["passed"] == false)
        .map(|check| &check["check"])
        .collect();
    assert_eq!(failing, [&json!("confinement")], "{checks:?}");
}
