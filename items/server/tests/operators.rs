mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use serde_json::json;

const PASSWORD: &str = "correct horse battery";

/// A human operator holding `capabilities` through a global role, and their
/// access token.
async fn operator(app: &TestApp, email: &str, capabilities: &[&str]) -> String {
    let subject = app.human(email, PASSWORD).await;
    if !capabilities.is_empty() {
        let role = format!("ops-{}", uuid::Uuid::now_v7().simple());
        let policies: Vec<_> = capabilities
            .iter()
            .map(|c| json!({"action": c, "effect": "allow"}))
            .collect();
        let put = app
            .control(
                Method::PUT,
                &format!("/v1/tenants/root/roles/{role}"),
                Some(json!({"policies": policies})),
            )
            .await;
        assert_eq!(put.status, StatusCode::OK, "{:?}", put.body);
        app.control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": role})),
        )
        .await;
    }
    app.login(email, PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn as_operator(
    app: &TestApp,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> common::Reply {
    let auth = format!("Bearer {token}");
    app.send(method, uri, &[("authorization", &auth)], body)
        .await
}

// r[verify authz.control-plane.capability]
// r[verify authz.assignment.capabilities]
#[tokio::test(flavor = "multi_thread")]
async fn operators_need_the_capability_for_each_area() {
    let app = TestApp::new().await;
    let nobody = operator(&app, "nobody@example.com", &[]).await;
    let people = operator(&app, "people@example.com", &["konklav:subjects:manage"]).await;
    let root = operator(&app, "root@example.com", &["konklav:control:all"]).await;
    let subject = uuid::Uuid::now_v7();
    let create = |token: &str| {
        let uri = format!("/v1/subjects/{subject}");
        let token = token.to_owned();
        let app = &app;
        async move {
            as_operator(
                app,
                &token,
                Method::PUT,
                &uri,
                Some(json!({"kind": "human"})),
            )
            .await
        }
    };

    assert_eq!(create(&nobody).await.code(), "FORBIDDEN");
    assert_eq!(create(&people).await.status, StatusCode::CREATED);
    let sessions = as_operator(&app, &people, Method::GET, "/v1/sessions", None).await;
    assert_eq!(
        sessions.code(),
        "FORBIDDEN",
        "subjects:manage doesn't cover sessions"
    );
    assert_eq!(
        as_operator(&app, &root, Method::GET, "/v1/sessions", None)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        as_operator(&app, &root, Method::GET, "/v1/signing-keys", None)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        as_operator(&app, "garbage", Method::GET, "/v1/sessions", None)
            .await
            .code(),
        "UNAUTHENTICATED"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn catalog_documents_cannot_touch_capabilities() {
    let app = TestApp::new().await;
    let reply = app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({"actions": [{"name": "konklav:control:all"}]})),
        )
        .await;
    assert_eq!(reply.code(), "INVALID_REQUEST");
    // Replacing the catalog keeps the built-in capabilities usable.
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "x:y"}]})),
    )
    .await;
    let role = app
        .control(
            Method::PUT,
            "/v1/tenants/root/roles/ops",
            Some(json!({"policies": [{"action": "konklav:sessions:manage", "effect": "allow"}]})),
        )
        .await;
    assert_eq!(role.status, StatusCode::OK, "{:?}", role.body);
    let catalog = app.control(Method::GET, "/v1/catalog", None).await;
    assert!(
        !catalog.body.to_string().contains("konklav:"),
        "built-ins aren't part of the document"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn groups_never_grant_capabilities() {
    let app = TestApp::new().await;
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "a:b"}], "groups": [{"name": "sys:all", "all_except_prefixes": []}]})),
    )
    .await;
    let token = operator(&app, "everything@example.com", &["sys:all"]).await;
    let reply = as_operator(&app, &token, Method::GET, "/v1/sessions", None).await;
    assert_eq!(reply.code(), "FORBIDDEN");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bootstrap_token_is_optional() {
    let app = TestApp::without_bootstrap().await;
    let reply = app.control(Method::GET, "/v1/sessions", None).await;
    assert_eq!(reply.code(), "UNAUTHENTICATED");
}

#[tokio::test(flavor = "multi_thread")]
async fn lists_subjects_tenants_and_memberships() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    app.human("bob@example.com", PASSWORD).await;
    let found = app
        .control(Method::GET, "/v1/subjects?identifier=ADA@example.com", None)
        .await;
    assert_eq!(found.body["subjects"].as_array().unwrap().len(), 1);
    assert_eq!(found.body["subjects"][0]["id"], ada.as_str());
    let page = app
        .control(Method::GET, "/v1/subjects?kind=human&limit=1", None)
        .await;
    assert_eq!(page.body["subjects"].as_array().unwrap().len(), 1);
    assert!(page.body["next"].is_string());

    let parent = uuid::Uuid::now_v7();
    let child = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{parent}"),
        Some(json!({})),
    )
    .await;
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{child}"),
        Some(json!({"parent": parent})),
    )
    .await;
    let children = app
        .control(Method::GET, &format!("/v1/tenants?parent={parent}"), None)
        .await;
    assert_eq!(children.body["tenants"].as_array().unwrap().len(), 1);
    assert_eq!(children.body["tenants"][0]["id"], child.to_string());

    let membership = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/memberships/{membership}"),
        Some(json!({"subject": ada, "tenant": child})),
    )
    .await;
    let members = app
        .control(
            Method::GET,
            &format!("/v1/tenants/{child}/memberships?active=true"),
            None,
        )
        .await;
    assert_eq!(members.body.as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn explains_entitlements() {
    let app = TestApp::new().await;
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "project:read"}]})),
    )
    .await;
    let tenant = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        Some(json!({})),
    )
    .await;
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}/roles/reader"),
        Some(json!({"policies": [{"action": "project:read", "effect": "allow"}]})),
    )
    .await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    let membership = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/memberships/{membership}"),
        Some(json!({"subject": ada, "tenant": tenant})),
    )
    .await;
    app.control(
        Method::POST,
        &format!("/v1/memberships/{membership}/assignments"),
        Some(json!({"role": "reader"})),
    )
    .await;
    let explained = app
        .control(
            Method::GET,
            &format!("/v1/subjects/{ada}/explain?tenant={tenant}&action=project:read"),
            None,
        )
        .await;
    assert_eq!(explained.status, StatusCode::OK, "{:?}", explained.body);
    assert_eq!(explained.body["granted_at"], json!(["tenant"]));
    assert!(
        explained.body["contributions"][0]["assignment"]
            .as_str()
            .unwrap()
            .starts_with("reader (")
    );
}

// r[verify federation.break-glass]
#[tokio::test(flavor = "multi_thread")]
async fn break_glass_logins_are_recorded() {
    let app = TestApp::new().await;
    let service = app.service_token().await;
    let subject = app
        .human("glass@example.com", "correct horse battery")
        .await;
    app.human("everyday@example.com", "correct horse battery")
        .await;
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    let credential = detail.body["credentials"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let marked = app
        .control(
            Method::PUT,
            &format!("/v1/credentials/{credential}/break-glass"),
            Some(json!({"break_glass": true})),
        )
        .await;
    assert_eq!(marked.status, StatusCode::OK, "{:?}", marked.body);
    assert_eq!(marked.body["break_glass"], true);

    app.login("everyday@example.com", "correct horse battery")
        .await;
    let login = app
        .login("glass@example.com", "correct horse battery")
        .await;
    assert_eq!(login.status, StatusCode::OK);
    let events = app
        .with_bearer(
            Method::GET,
            "/v1/events/batch?after=0&kinds=break_glass.used",
            &service,
        )
        .await;
    let used: Vec<_> = events.body["events"].as_array().unwrap().iter().collect();
    assert_eq!(used.len(), 1, "{:?}", events.body);
    assert_eq!(used[0]["payload"]["subject"], subject.as_str());
    assert_eq!(used[0]["payload"]["credential"], credential.as_str());
}

// r[verify authz.control-plane.own-capabilities]
#[tokio::test(flavor = "multi_thread")]
async fn operators_read_their_own_capabilities() {
    let app = TestApp::new().await;
    let people = operator(&app, "people@example.com", &["konklav:subjects:manage"]).await;
    let nobody = operator(&app, "nobody@example.com", &[]).await;
    let own = app
        .with_bearer(Method::GET, "/v1/capabilities", &people)
        .await;
    assert_eq!(own.status, StatusCode::OK, "{:?}", own.body);
    assert_eq!(own.body["capabilities"], json!(["konklav:subjects:manage"]));
    let claims = app.verify(&people).await;
    assert_eq!(own.body["subject"], claims.sub.to_string());

    let none = app
        .with_bearer(Method::GET, "/v1/capabilities", &nobody)
        .await;
    assert_eq!(none.body["capabilities"], json!([]));
    let anonymous = app.send(Method::GET, "/v1/capabilities", &[], None).await;
    assert_eq!(anonymous.code(), "UNAUTHENTICATED");
}

/// A human operator assigned the built-in role `role`, and their access
/// token.
async fn builtin_operator(app: &TestApp, email: &str, role: &str) -> (String, String) {
    let subject = app.human(email, PASSWORD).await;
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": role})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    let token = app.login(email, PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (subject, token)
}

// r[verify authz.role.builtin]
// r[verify authz.role.builtin.set]
#[tokio::test(flavor = "multi_thread")]
async fn the_builtin_admin_role_runs_the_control_plane_but_not_impersonation() {
    let app = TestApp::new().await;
    let roles = app
        .control(Method::GET, "/v1/tenants/root/roles", None)
        .await;
    let builtin: Vec<_> = roles
        .body
        .as_array()
        .unwrap()
        .iter()
        .filter(|role| role["builtin"] == json!(true))
        .map(|role| role["key"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(builtin, ["konklav.admin", "konklav.delivery"]);

    let (admin, token) = builtin_operator(&app, "admin@example.com", "konklav.admin").await;
    for uri in [
        "/v1/sessions",
        "/v1/signing-keys",
        "/v1/tenants",
        "/v1/catalog",
    ] {
        let reply = as_operator(&app, &token, Method::GET, uri, None).await;
        assert_eq!(reply.status, StatusCode::OK, "{uri}: {:?}", reply.body);
    }
    let invite = as_operator(
        &app,
        &token,
        Method::POST,
        "/v1/invites",
        Some(json!({"email": "new@example.com"})),
    )
    .await;
    assert_eq!(invite.status, StatusCode::CREATED, "{:?}", invite.body);

    let target = app.human("someone@example.com", PASSWORD).await;
    let impersonating = as_operator(
        &app,
        &token,
        Method::POST,
        "/v1/impersonate",
        Some(json!({"subject": target})),
    )
    .await;
    assert_eq!(impersonating.code(), "FORBIDDEN");
    let capabilities = as_operator(&app, &token, Method::GET, "/v1/capabilities", None).await;
    let held = capabilities.body["capabilities"].to_string();
    assert!(!held.contains("konklav:delivery:read"), "{held}");

    let explained = app
        .control(
            Method::GET,
            &format!("/v1/subjects/{admin}/explain?action=konklav:control:all"),
            None,
        )
        .await;
    assert_eq!(explained.status, StatusCode::OK, "{:?}", explained.body);
    assert!(
        explained.body["contributions"][0]["assignment"]
            .as_str()
            .unwrap()
            .starts_with("konklav.admin (")
    );
}

// r[verify authz.role.builtin]
// r[verify authz.role.reserved-key]
#[tokio::test(flavor = "multi_thread")]
async fn builtin_roles_and_reserved_keys_cannot_be_written() {
    let app = TestApp::new().await;
    let before = app
        .control(Method::GET, "/v1/tenants/root/roles/konklav.admin", None)
        .await;
    assert_eq!(before.status, StatusCode::OK, "{:?}", before.body);

    let replaced = app
        .control(
            Method::PUT,
            "/v1/tenants/root/roles/konklav.admin",
            Some(json!({"policies": []})),
        )
        .await;
    assert_eq!(replaced.code(), "INVALID_REQUEST");
    let deleted = app
        .control(Method::DELETE, "/v1/tenants/root/roles/konklav.admin", None)
        .await;
    assert_eq!(deleted.code(), "INVALID_REQUEST");
    let created = app
        .control(
            Method::PUT,
            "/v1/tenants/root/roles/konklav.custom",
            Some(json!({"policies": []})),
        )
        .await;
    assert_eq!(created.code(), "INVALID_REQUEST");

    let tenant = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        Some(json!({})),
    )
    .await;
    let local = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}/roles/konklav.local"),
            Some(json!({"policies": []})),
        )
        .await;
    assert_eq!(local.code(), "INVALID_REQUEST");

    // Replacing the catalog leaves built-in roles granting.
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "x:y"}]})),
    )
    .await;
    let after = app
        .control(Method::GET, "/v1/tenants/root/roles/konklav.admin", None)
        .await;
    assert_eq!(after.body, before.body);
    let (_, token) = builtin_operator(&app, "admin@example.com", "konklav.admin").await;
    let sessions = as_operator(&app, &token, Method::GET, "/v1/sessions", None).await;
    assert_eq!(sessions.status, StatusCode::OK, "{:?}", sessions.body);
}

// r[verify authz.control-plane.escalation]
#[tokio::test(flavor = "multi_thread")]
async fn narrower_capabilities_cannot_lead_to_more() {
    let app = TestApp::new().await;
    let authz = operator(&app, "authz@example.com", &["konklav:authz:manage"]).await;
    let people = operator(&app, "people@example.com", &["konklav:subjects:manage"]).await;
    let admin = app.human("admin@example.com", PASSWORD).await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{admin}/global-assignments"),
        Some(json!({"role": "konklav.admin"})),
    )
    .await;
    let me = app.verify(&authz).await.sub;

    let assign_admin = as_operator(
        &app,
        &authz,
        Method::POST,
        &format!("/v1/subjects/{me}/global-assignments"),
        Some(json!({"role": "konklav.admin"})),
    )
    .await;
    assert_eq!(assign_admin.code(), "FORBIDDEN", "{:?}", assign_admin.body);
    let capability_role = as_operator(
        &app,
        &authz,
        Method::PUT,
        "/v1/tenants/root/roles/sneaky",
        Some(json!({"policies": [{"action": "konklav:control:all", "effect": "allow"}]})),
    )
    .await;
    assert_eq!(
        capability_role.code(),
        "FORBIDDEN",
        "{:?}",
        capability_role.body
    );
    let capability_template = as_operator(
        &app,
        &authz,
        Method::PUT,
        "/v1/templates/sneaky",
        Some(json!({"policies": [{"action": "konklav:control:all", "effect": "allow"}]})),
    )
    .await;
    assert_eq!(capability_template.code(), "FORBIDDEN");
    let plain_role = as_operator(
        &app,
        &authz,
        Method::PUT,
        "/v1/tenants/root/roles/plain",
        Some(json!({"policies": []})),
    )
    .await;
    assert_eq!(plain_role.status, StatusCode::OK, "{:?}", plain_role.body);

    let credentials = app
        .control(Method::GET, &format!("/v1/subjects/{admin}"), None)
        .await;
    let password = credentials.body["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "password")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let replaced = as_operator(
        &app,
        &people,
        Method::POST,
        &format!("/v1/credentials/{password}/replace"),
        Some(json!({"password": "taken over now"})),
    )
    .await;
    assert_eq!(replaced.code(), "FORBIDDEN", "{:?}", replaced.body);
    let disabled = as_operator(
        &app,
        &people,
        Method::POST,
        &format!("/v1/subjects/{admin}/disable"),
        None,
    )
    .await;
    assert_eq!(disabled.code(), "FORBIDDEN");
    let plain = app.human("plain@example.com", PASSWORD).await;
    let disabled = as_operator(
        &app,
        &people,
        Method::POST,
        &format!("/v1/subjects/{plain}/disable"),
        None,
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{:?}", disabled.body);
}

// r[verify platform.config.bootstrap-token]
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_bootstrap_token_is_refused() {
    let app = TestApp::with_auth(|auth| {
        auth.control_token_expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
    })
    .await;
    let refused = app.control(Method::GET, "/v1/subjects", None).await;
    assert_eq!(refused.code(), "UNAUTHENTICATED", "{:?}", refused.body);
}
