//! Access requests: people ask for a membership in a tenant that takes
//! requests, and operators approve or deny on the control plane.

#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashSet;

use axum::http::{Method, StatusCode};
use common::TestApp;
use konklav_core::TenantId;
use konklav_server::access_requests::Settings;
use konklav_store::tenants::Reference;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

/// An app where `tenants` take requests (every tenant when `None`), and
/// a denied subject may ask again after `retry`.
async fn app(tenants: Option<&[uuid::Uuid]>, retry: chrono::Duration) -> TestApp {
    let tenants = tenants.map(|ids| {
        ids.iter()
            .copied()
            .map(|id| Reference::Id(TenantId::from(id)))
            .collect::<HashSet<_>>()
    });
    TestApp::with_auth(|auth| {
        auth.access_requests = Some(Settings {
            tenants,
            retry_after_denial: retry,
        });
    })
    .await
}

async fn tenant(app: &TestApp) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    let created = app
        .control(Method::PUT, &format!("/v1/tenants/{id}"), Some(json!({})))
        .await;
    assert!(created.status.is_success(), "{:?}", created.body);
    id
}

/// Signs a new person in, returning their access token.
async fn person(app: &TestApp, email: &str) -> String {
    app.human(email, PASSWORD).await;
    let login = app.login(email, PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    login.body["access_token"].as_str().unwrap().to_owned()
}

async fn as_person(
    app: &TestApp,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> common::Reply {
    let auth = format!("Bearer {token}");
    app.send(method, path, &[("authorization", &auth)], body)
        .await
}

async fn ask(app: &TestApp, token: &str, tenant: impl std::fmt::Display) -> common::Reply {
    as_person(
        app,
        token,
        Method::POST,
        &format!("/v1/tenants/{tenant}/access-request"),
        None,
    )
    .await
}

/// The states of the `access_request.changed` events so far.
async fn changes(app: &TestApp) -> Vec<String> {
    let mut conn = app.state.pool.get().await.unwrap();
    konklav_store::events::after(&mut conn, konklav_core::Cursor::new(0), 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "access_request.changed")
        .map(|event| event.payload["state"].as_str().unwrap().to_owned())
        .collect()
}

// r[verify membership.access-request]
// r[verify membership.access-request.decision]
// r[verify membership.access-request.event]
#[tokio::test(flavor = "multi_thread")]
async fn people_ask_and_operators_approve_with_roles() {
    let tenant_id = uuid::Uuid::now_v7();
    let app = app(Some(&[tenant_id]), chrono::Duration::hours(1)).await;
    for (method, path, body) in [
        (
            Method::PUT,
            "/v1/catalog".to_owned(),
            json!({"actions": [{"name": "registry:pull"}]}),
        ),
        (Method::PUT, format!("/v1/tenants/{tenant_id}"), json!({})),
        (
            Method::PUT,
            format!("/v1/tenants/{tenant_id}/roles/viewer"),
            json!({"policies": [{"action": "registry:pull", "effect": "allow"}]}),
        ),
    ] {
        let reply = app.control(method, &path, Some(body)).await;
        assert!(reply.status.is_success(), "{path}: {:?}", reply.body);
    }
    let ada = person(&app, "ada@example.com").await;

    let entering = as_person(
        &app,
        &ada,
        Method::POST,
        "/v1/login/tenant",
        Some(json!({"tenant": tenant_id})),
    )
    .await;
    assert_eq!(entering.status, StatusCode::FORBIDDEN, "not a member yet");

    let asked = ask(&app, &ada, tenant_id).await;
    assert_eq!(asked.status, StatusCode::CREATED, "{:?}", asked.body);
    assert_eq!(asked.body["state"], "pending");
    let id = asked.body["id"].as_str().unwrap().to_owned();
    let again = ask(&app, &ada, tenant_id).await;
    assert_eq!(again.status, StatusCode::OK, "the pending one answers");
    assert_eq!(again.body["id"], id.as_str());
    let own = as_person(
        &app,
        &ada,
        Method::GET,
        &format!("/v1/tenants/{tenant_id}/access-request"),
        None,
    )
    .await;
    assert_eq!(own.body["id"], id.as_str());

    let pending = app
        .control(
            Method::GET,
            &format!("/v1/access-requests?tenant={tenant_id}&state=pending"),
            None,
        )
        .await;
    assert_eq!(pending.status, StatusCode::OK, "{:?}", pending.body);
    assert_eq!(pending.body["access_requests"][0]["id"], id.as_str());

    let approved = app
        .control(
            Method::POST,
            &format!("/v1/access-requests/{id}/approve"),
            Some(json!({"roles": ["viewer"]})),
        )
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{:?}", approved.body);
    assert_eq!(approved.body["state"], "approved");
    assert!(approved.body["cursor"].is_number());
    let membership = approved.body["membership_id"].as_str().unwrap().to_owned();
    let detail = app
        .control(Method::GET, &format!("/v1/memberships/{membership}"), None)
        .await;
    assert_eq!(detail.body["tenant_id"], tenant_id.to_string());
    assert_eq!(detail.body["assignments"].as_array().unwrap().len(), 1);

    let entered = as_person(
        &app,
        &ada,
        Method::POST,
        "/v1/login/tenant",
        Some(json!({"tenant": tenant_id})),
    )
    .await;
    assert_eq!(entered.status, StatusCode::OK, "{:?}", entered.body);
    // Entering the tenant moved the session on to a new version.
    let ada = entered.body["access_token"].as_str().unwrap().to_owned();

    // Decided once: approving again answers the same, denying fails, and a
    // member has nothing to ask.
    let repeated = app
        .control(
            Method::POST,
            &format!("/v1/access-requests/{id}/approve"),
            Some(json!({})),
        )
        .await;
    assert_eq!(repeated.status, StatusCode::OK);
    assert_eq!(repeated.body["membership_id"], membership.as_str());
    let denied = app
        .control(
            Method::POST,
            &format!("/v1/access-requests/{id}/deny"),
            None,
        )
        .await;
    assert_eq!(denied.status, StatusCode::CONFLICT);
    assert_eq!(
        ask(&app, &ada, tenant_id).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(changes(&app).await, ["pending", "approved"]);
}

// r[verify membership.access-request.disclosure]
#[tokio::test(flavor = "multi_thread")]
async fn tenants_that_take_no_requests_answer_like_missing_ones() {
    let listed = uuid::Uuid::now_v7();
    let app = app(Some(&[listed]), chrono::Duration::hours(1)).await;
    let created = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{listed}"),
            Some(json!({})),
        )
        .await;
    assert!(created.status.is_success());
    let unlisted = tenant(&app).await;
    let ada = person(&app, "ada@example.com").await;

    let refusals = [
        ask(&app, &ada, unlisted).await,
        ask(&app, &ada, uuid::Uuid::now_v7()).await,
    ];
    let suspended = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{listed}/state"),
            Some(json!({"state": "suspended"})),
        )
        .await;
    assert!(suspended.status.is_success(), "{:?}", suspended.body);
    let suspended = ask(&app, &ada, listed).await;
    for refusal in refusals.iter().chain([&suspended]) {
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        assert_eq!(refusal.body, refusals[0].body);
    }

    // Without access requests configured, nobody can ask.
    let off = TestApp::new().await;
    let tenant = tenant(&off).await;
    let bo = person(&off, "bo@example.com").await;
    let refused = ask(&off, &bo, tenant).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body, refusals[0].body);
}

// r[verify membership.access-request.retry]
#[tokio::test(flavor = "multi_thread")]
async fn a_denied_person_waits_before_asking_again() {
    let app = app(None, chrono::Duration::hours(1)).await;
    let tenant = tenant(&app).await;
    let ada = person(&app, "ada@example.com").await;
    let id = ask(&app, &ada, tenant).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let denied = app
        .control(
            Method::POST,
            &format!("/v1/access-requests/{id}/deny"),
            None,
        )
        .await;
    assert_eq!(denied.status, StatusCode::OK, "{:?}", denied.body);
    assert_eq!(denied.body["state"], "denied");
    let again = ask(&app, &ada, tenant).await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);
    assert!(
        again.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("denied"),
        "{:?}",
        again.body
    );

    let impatient = self::app(None, chrono::Duration::zero()).await;
    let tenant = self::tenant(&impatient).await;
    let bo = person(&impatient, "bo@example.com").await;
    let id = ask(&impatient, &bo, tenant).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    impatient
        .control(
            Method::POST,
            &format!("/v1/access-requests/{id}/deny"),
            None,
        )
        .await;
    assert_eq!(
        ask(&impatient, &bo, tenant).await.status,
        StatusCode::CREATED
    );
}

// r[verify membership.access-request.decision]
#[tokio::test(flavor = "multi_thread")]
async fn people_withdraw_their_pending_requests() {
    let app = app(None, chrono::Duration::hours(1)).await;
    let tenant = tenant(&app).await;
    let ada = person(&app, "ada@example.com").await;
    let id = ask(&app, &ada, tenant).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/v1/tenants/{tenant}/access-request");
    let withdrawn = as_person(&app, &ada, Method::DELETE, &path, None).await;
    assert_eq!(withdrawn.status, StatusCode::OK, "{:?}", withdrawn.body);
    assert_eq!(withdrawn.body["state"], "withdrawn");
    assert_eq!(
        as_person(&app, &ada, Method::DELETE, &path, None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let approved = app
        .control(
            Method::POST,
            &format!("/v1/access-requests/{id}/approve"),
            Some(json!({})),
        )
        .await;
    assert_eq!(approved.status, StatusCode::CONFLICT);
    assert_eq!(changes(&app).await, ["pending", "withdrawn"]);
}

/// A tenant with `viewer` and `editor`, ordinary roles, and `admitter`,
/// which names the tenant capability `konklav:tenant:admit`.
async fn admitting_tenant(app: &TestApp) -> uuid::Uuid {
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "record:read"}, {"name": "record:write"}]})),
    )
    .await;
    let tenant = tenant(app).await;
    for (role, action) in [
        ("viewer", "record:read"),
        ("editor", "record:write"),
        ("admitter", "konklav:tenant:admit"),
    ] {
        let written = app
            .control(
                Method::PUT,
                &format!("/v1/tenants/{tenant}/roles/{role}"),
                Some(json!({"policies": [{"action": action, "effect": "allow"}]})),
            )
            .await;
        assert!(written.status.is_success(), "{:?}", written.body);
    }
    tenant
}

/// A signed-in member of `tenant` with `roles`: their subject and token.
async fn member(
    app: &TestApp,
    tenant: uuid::Uuid,
    email: &str,
    roles: &[&str],
) -> (String, String) {
    let subject = app.human(email, PASSWORD).await;
    let membership = uuid::Uuid::now_v7();
    let joined = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": subject, "tenant": tenant})),
        )
        .await;
    assert!(joined.status.is_success(), "{:?}", joined.body);
    for role in roles {
        let assigned = app
            .control(
                Method::POST,
                &format!("/v1/memberships/{membership}/assignments"),
                Some(json!({"role": role})),
            )
            .await;
        assert!(assigned.status.is_success(), "{:?}", assigned.body);
    }
    let login = app.login(email, PASSWORD).await;
    (
        subject,
        login.body["access_token"].as_str().unwrap().to_owned(),
    )
}

async fn decide(
    app: &TestApp,
    token: &str,
    tenant: impl std::fmt::Display,
    id: &str,
    how: &str,
    body: Option<Value>,
) -> common::Reply {
    as_person(
        app,
        token,
        Method::POST,
        &format!("/v1/tenants/{tenant}/access-requests/{id}/{how}"),
        body,
    )
    .await
}

// r[verify membership.access-request.tenant]
// r[verify membership.access-request.decider]
// r[verify authz.tenant-capability]
#[tokio::test(flavor = "multi_thread")]
async fn members_holding_admit_decide_requests_to_their_tenant() {
    let app = app(None, chrono::Duration::hours(1)).await;
    let tenant = admitting_tenant(&app).await;
    let other = admitting_tenant(&app).await;
    let (admin, admin_token) =
        member(&app, tenant, "admin@example.com", &["admitter", "viewer"]).await;
    let bo = person(&app, "bo@example.com").await;
    let carl = person(&app, "carl@example.com").await;
    let id = ask(&app, &bo, tenant).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let elsewhere = ask(&app, &carl, other).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let listed = as_person(
        &app,
        &admin_token,
        Method::GET,
        &format!("/v1/tenants/{tenant}/access-requests?state=pending"),
        None,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let ids: Vec<&str> = listed.body["access_requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|request| request["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [id.as_str()], "only the tenant's requests");

    // Only in their own tenant, and a request elsewhere isn't found there.
    let foreign = as_person(
        &app,
        &admin_token,
        Method::GET,
        &format!("/v1/tenants/{other}/access-requests"),
        None,
    )
    .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    let misplaced = decide(&app, &admin_token, tenant, &elsewhere, "deny", None).await;
    assert_eq!(misplaced.status, StatusCode::NOT_FOUND);

    // Only roles the admin holds, and none naming a konklav: action.
    let beyond = decide(
        &app,
        &admin_token,
        tenant,
        &id,
        "approve",
        Some(json!({"roles": ["editor"]})),
    )
    .await;
    assert_eq!(beyond.status, StatusCode::FORBIDDEN, "{:?}", beyond.body);
    let spreading = decide(
        &app,
        &admin_token,
        tenant,
        &id,
        "approve",
        Some(json!({"roles": ["admitter"]})),
    )
    .await;
    assert_eq!(
        spreading.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        spreading.body
    );

    let approved = decide(
        &app,
        &admin_token,
        tenant,
        &id,
        "approve",
        Some(json!({"roles": ["viewer"]})),
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "{:?}", approved.body);
    assert_eq!(approved.body["state"], "approved");
    assert_eq!(approved.body["decided_by"], admin.as_str());
    let shown = app
        .control(Method::GET, &format!("/v1/access-requests/{id}"), None)
        .await;
    assert_eq!(shown.body["decided_by"], admin.as_str());

    // A member without the capability can't decide.
    let (_, viewer) = member(&app, tenant, "dana@example.com", &["viewer"]).await;
    let refused = as_person(
        &app,
        &viewer,
        Method::GET,
        &format!("/v1/tenants/{tenant}/access-requests"),
        None,
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

// r[verify membership.access-request.tenant]
#[tokio::test(flavor = "multi_thread")]
async fn no_one_decides_their_own_request() {
    let app = app(None, chrono::Duration::hours(1)).await;
    let tenant = admitting_tenant(&app).await;
    // Admit everywhere through a global role, without being a member.
    let role = app
        .control(
            Method::PUT,
            "/v1/tenants/root/roles/admit-anywhere",
            Some(json!({"policies": [{"action": "konklav:tenant:admit", "effect": "allow"}]})),
        )
        .await;
    assert!(role.status.is_success(), "{:?}", role.body);
    let erin = app.human("erin@example.com", PASSWORD).await;
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{erin}/global-assignments"),
            Some(json!({"role": "admit-anywhere"})),
        )
        .await;
    assert!(assigned.status.is_success(), "{:?}", assigned.body);
    let token = app.login("erin@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = ask(&app, &token, tenant).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for how in ["approve", "deny"] {
        let own = decide(&app, &token, tenant, &id, how, Some(json!({}))).await;
        assert_eq!(own.status, StatusCode::FORBIDDEN, "{how}: {:?}", own.body);
    }
}

// r[verify authz.control-plane.escalation]
#[tokio::test(flavor = "multi_thread")]
async fn operators_need_control_all_to_approve_into_roles_naming_konklav_actions() {
    let app = app(None, chrono::Duration::hours(1)).await;
    let tenant = admitting_tenant(&app).await;
    let role = app
        .control(
            Method::PUT,
            "/v1/tenants/root/roles/tenancy",
            Some(json!({"policies": [{"action": "konklav:tenants:manage", "effect": "allow"}]})),
        )
        .await;
    assert!(role.status.is_success(), "{:?}", role.body);
    let operator = app.human("ops@example.com", PASSWORD).await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{operator}/global-assignments"),
        Some(json!({"role": "tenancy"})),
    )
    .await;
    let token = app.login("ops@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let bo = person(&app, "bo@example.com").await;
    let id = ask(&app, &bo, tenant).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/v1/access-requests/{id}/approve");
    let escalating = as_person(
        &app,
        &token,
        Method::POST,
        &path,
        Some(json!({"roles": ["admitter"]})),
    )
    .await;
    assert_eq!(
        escalating.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        escalating.body
    );
    let approved = as_person(
        &app,
        &token,
        Method::POST,
        &path,
        Some(json!({"roles": ["viewer"]})),
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "{:?}", approved.body);
    assert_eq!(approved.body["decided_by"], operator.as_str());
}
