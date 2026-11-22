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

/// A human holding the built-in admin role, and their password credential.
async fn admin(app: &TestApp, email: &str) -> (String, String) {
    let subject = app.human(email, PASSWORD).await;
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": "konklav.admin"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    let credential = detail.body["credentials"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    (subject, credential)
}

/// A service principal with a secret key: its id and the key's.
async fn service(app: &TestApp) -> (String, String) {
    let id = uuid::Uuid::now_v7().to_string();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{id}"),
        Some(json!({"kind": "service"})),
    )
    .await;
    let created = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{id}/credentials"),
            Some(json!({"kind": "secret_key"})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let key = created.body["secret_keys"]["a"]
        .as_str()
        .unwrap()
        .split_once('.')
        .unwrap()
        .0
        .to_owned();
    (id, key)
}

// r[verify authz.control-plane.escalation]
#[tokio::test(flavor = "multi_thread")]
async fn rotating_an_operators_secret_key_needs_every_capability() {
    let app = TestApp::new().await;
    let people = operator(&app, "people@example.com", &["konklav:subjects:manage"]).await;
    let (robot, robot_key) = service(&app).await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{robot}/global-assignments"),
        Some(json!({"role": "konklav.admin"})),
    )
    .await;
    let (_, plain_key) = service(&app).await;

    let rotated = as_operator(
        &app,
        &people,
        Method::POST,
        &format!("/v1/credentials/{robot_key}/slots/a/rotate"),
        None,
    )
    .await;
    assert_eq!(rotated.code(), "FORBIDDEN", "{:?}", rotated.body);
    let rotated = as_operator(
        &app,
        &people,
        Method::POST,
        &format!("/v1/credentials/{plain_key}/slots/a/rotate"),
        None,
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);
    let rotated = app
        .control(
            Method::POST,
            &format!("/v1/credentials/{robot_key}/slots/a/rotate"),
            None,
        )
        .await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);
}

/// Produced by Python's argon2-cffi for "swordfish".
const SWORDFISH: &str = "$argon2id$v=19$m=65536,t=3,p=4$AIuJ/bg0xA1dNFOl/Y8xkw$gKt+ObjIzIEnOSKX6cVpsSdoPA5zgkfSkXwBXGlf/88";

// r[verify authz.control-plane.escalation]
#[tokio::test(flavor = "multi_thread")]
async fn importing_cannot_lead_to_more_capabilities() {
    let app = TestApp::new().await;
    let importer = operator(&app, "import@example.com", &["konklav:import"]).await;
    let (boss, boss_password) = admin(&app, "boss@example.com").await;
    let plain = app.human("plain@example.com", PASSWORD).await;

    // A second password for the admin, which the importer knows.
    let planted = as_operator(
        &app,
        &importer,
        Method::POST,
        "/v1/import/credentials",
        Some(password_record(
            &boss,
            uuid::Uuid::now_v7(),
            "backdoor@example.com",
        )),
    )
    .await;
    assert_eq!(planted.code(), "FORBIDDEN", "{:?}", planted.body);
    let login = app.login("backdoor@example.com", "swordfish").await;
    assert_eq!(login.code(), "INVALID_CREDENTIALS", "{:?}", login.body);

    // A session for the admin, whose refresh token the importer knows.
    let session = |subject: &str, credential: &str| {
        json!({"sessions": [{
            "id": uuid::Uuid::now_v7(), "subject": subject, "credential": credential,
            "stage": "identity", "amr": ["pwd"], "auth_time": "2026-10-01T00:00:00Z",
            "version": 1, "refresh_hash": "00".repeat(32),
            "expires_at": (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
        }]})
    };
    let carried = as_operator(
        &app,
        &importer,
        Method::POST,
        "/v1/import/sessions",
        Some(session(&boss, &boss_password)),
    )
    .await;
    assert_eq!(carried.code(), "FORBIDDEN", "{:?}", carried.body);

    // An MFA factor for the admin, whose seed the importer knows.
    let factor = |subject: &str| {
        json!({"factors": [{
            "id": uuid::Uuid::now_v7(), "subject": subject, "kind": "totp",
            "seed_base32": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        }]})
    };
    let enrolled = as_operator(
        &app,
        &importer,
        Method::POST,
        "/v1/import/mfa-factors",
        Some(factor(&boss)),
    )
    .await;
    assert_eq!(enrolled.code(), "FORBIDDEN", "{:?}", enrolled.body);

    // Disabling the admin.
    let disabled = as_operator(
        &app,
        &importer,
        Method::POST,
        "/v1/import/subjects",
        Some(json!({"subjects": [{"id": boss, "kind": "human", "state": "disabled"}]})),
    )
    .await;
    assert_eq!(disabled.code(), "FORBIDDEN", "{:?}", disabled.body);
    let login = app.login("boss@example.com", PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);

    // A subject without capabilities takes the same kind of record.
    let enrolled = as_operator(
        &app,
        &importer,
        Method::POST,
        "/v1/import/mfa-factors",
        Some(factor(&plain)),
    )
    .await;
    assert_eq!(enrolled.status, StatusCode::OK, "{:?}", enrolled.body);
}

/// An import record giving `subject` a password the importer knows.
fn password_record(subject: &str, id: uuid::Uuid, identifier: &str) -> serde_json::Value {
    json!({"credentials": [{
        "id": id, "subject": subject, "identifier": identifier,
        "kind": "password", "password_hash": SWORDFISH,
    }]})
}

// r[verify authz.control-plane.escalation]
// r[verify import.idempotent]
#[tokio::test(flavor = "multi_thread")]
async fn an_import_can_be_rerun_once_its_subjects_are_operators() {
    let app = TestApp::new().await;
    let importer = operator(&app, "import@example.com", &["konklav:import"]).await;
    let plain = app.human("plain@example.com", PASSWORD).await;
    let later = uuid::Uuid::now_v7();
    let record = password_record(&plain, later, "later@example.com");
    let imported = as_operator(
        &app,
        &importer,
        Method::POST,
        "/v1/import/credentials",
        Some(record.clone()),
    )
    .await;
    assert_eq!(imported.body["imported"], 1, "{:?}", imported.body);

    // Once the subject is an operator, re-running the import skips its
    // credential and so passes, but a new one is refused.
    app.control(
        Method::POST,
        &format!("/v1/subjects/{plain}/global-assignments"),
        Some(json!({"role": "konklav.admin"})),
    )
    .await;
    let rerun = as_operator(
        &app,
        &importer,
        Method::POST,
        "/v1/import/credentials",
        Some(record),
    )
    .await;
    assert_eq!(rerun.body["skipped"], 1, "{:?}", rerun.body);
    let another = as_operator(
        &app,
        &importer,
        Method::POST,
        "/v1/import/credentials",
        Some(password_record(
            &plain,
            uuid::Uuid::now_v7(),
            "another@example.com",
        )),
    )
    .await;
    assert_eq!(another.code(), "FORBIDDEN", "{:?}", another.body);
}

// r[verify authz.control-plane.escalation]
#[tokio::test(flavor = "multi_thread")]
async fn denying_capabilities_needs_every_capability() {
    let app = TestApp::new().await;
    let authz = operator(&app, "authz@example.com", &["konklav:authz:manage"]).await;
    let (boss, _) = admin(&app, "boss@example.com").await;
    let deny = json!({"policies": [{"action": "konklav:control:all", "effect": "deny"}]});

    let role = as_operator(
        &app,
        &authz,
        Method::PUT,
        "/v1/tenants/root/roles/muzzle",
        Some(deny.clone()),
    )
    .await;
    assert_eq!(role.code(), "FORBIDDEN", "{:?}", role.body);
    let template = as_operator(
        &app,
        &authz,
        Method::PUT,
        "/v1/templates/muzzle",
        Some(deny.clone()),
    )
    .await;
    assert_eq!(template.code(), "FORBIDDEN", "{:?}", template.body);

    // Nor may a role someone else wrote be assigned, unassigned, rewritten
    // or deleted.
    let written = app
        .control(Method::PUT, "/v1/tenants/root/roles/muzzle", Some(deny))
        .await;
    assert_eq!(written.status, StatusCode::OK, "{:?}", written.body);
    let assign = json!({"role": "muzzle"});
    let assigned = as_operator(
        &app,
        &authz,
        Method::POST,
        &format!("/v1/subjects/{boss}/global-assignments"),
        Some(assign.clone()),
    )
    .await;
    assert_eq!(assigned.code(), "FORBIDDEN", "{:?}", assigned.body);
    let login = app.login("boss@example.com", PASSWORD).await;
    let boss_token = login.body["access_token"].as_str().unwrap();
    let still = as_operator(&app, boss_token, Method::GET, "/v1/sessions", None).await;
    assert_eq!(still.status, StatusCode::OK, "{:?}", still.body);

    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{boss}/global-assignments"),
            Some(assign),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    let assignment = assigned.body["id"].as_str().unwrap();
    let unassigned = as_operator(
        &app,
        &authz,
        Method::DELETE,
        &format!("/v1/assignments/{assignment}"),
        None,
    )
    .await;
    assert_eq!(unassigned.code(), "FORBIDDEN", "{:?}", unassigned.body);
    let emptied = as_operator(
        &app,
        &authz,
        Method::PUT,
        "/v1/tenants/root/roles/muzzle",
        Some(json!({"policies": []})),
    )
    .await;
    assert_eq!(emptied.code(), "FORBIDDEN", "{:?}", emptied.body);
    let deleted = as_operator(
        &app,
        &authz,
        Method::DELETE,
        "/v1/tenants/root/roles/muzzle",
        None,
    )
    .await;
    assert_eq!(deleted.code(), "FORBIDDEN", "{:?}", deleted.body);
}

/// Whether `people` may enable `subject`, replace its password `credential`
/// and give it another: all three, or none.
async fn may_take_over(app: &TestApp, people: &str, subject: &str, credential: &str) -> bool {
    let added = as_operator(
        app,
        people,
        Method::POST,
        &format!("/v1/subjects/{subject}/credentials"),
        Some(json!({
            "kind": "password", "password": "taken over now",
            "identifier": format!("{subject}@example.com"),
        })),
    )
    .await;
    let replaced = as_operator(
        app,
        people,
        Method::POST,
        &format!("/v1/credentials/{credential}/replace"),
        Some(json!({"password": "taken over now"})),
    )
    .await;
    let enabled = as_operator(
        app,
        people,
        Method::POST,
        &format!("/v1/subjects/{subject}/enable"),
        None,
    )
    .await;
    let replies = [added, replaced, enabled];
    if replies.iter().all(|reply| reply.status.is_success()) {
        return true;
    }
    for reply in replies {
        assert_eq!(reply.code(), "FORBIDDEN", "{:?}", reply.body);
    }
    false
}

// r[verify authz.control-plane.escalation]
#[tokio::test(flavor = "multi_thread")]
async fn a_disabled_operator_is_still_protected() {
    let app = TestApp::new().await;
    let people = operator(&app, "people@example.com", &["konklav:subjects:manage"]).await;
    let (boss, boss_password) = admin(&app, "boss@example.com").await;
    let plain = app.human("plain@example.com", PASSWORD).await;
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{plain}"), None)
        .await;
    let plain_password = detail.body["credentials"][0]["id"].as_str().unwrap();
    for subject in [&boss, &plain] {
        let disabled = app
            .control(
                Method::POST,
                &format!("/v1/subjects/{subject}/disable"),
                None,
            )
            .await;
        assert_eq!(disabled.status, StatusCode::OK, "{:?}", disabled.body);
    }

    assert!(!may_take_over(&app, &people, &boss, &boss_password).await);
    let login = app.login("boss@example.com", "taken over now").await;
    assert_eq!(login.code(), "INVALID_CREDENTIALS", "{:?}", login.body);
    assert!(may_take_over(&app, &people, &plain, plain_password).await);
}

/// A confidential OIDC client definition, bound to `service_subject`.
fn client(service_subject: Option<&str>) -> serde_json::Value {
    json!({
        "kind": "confidential", "audience": "reports",
        "redirect_uris": ["https://reports.example/callback"],
        "service_subject": service_subject,
    })
}

// r[verify authz.control-plane.escalation]
#[tokio::test(flavor = "multi_thread")]
async fn binding_a_client_to_an_operator_needs_every_capability() {
    let app = TestApp::new().await;
    let clients = operator(&app, "clients@example.com", &["konklav:clients:manage"]).await;
    let (robot, _) = service(&app).await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{robot}/global-assignments"),
        Some(json!({"role": "konklav.admin"})),
    )
    .await;
    let (plain, _) = service(&app).await;
    let put = |uri: &'static str, subject: Option<&str>| {
        as_operator(&app, &clients, Method::PUT, uri, Some(client(subject)))
    };

    // Neither a new client nor one of its own may be bound to the operator.
    let bound = put("/v1/oidc/clients/mine", Some(&robot)).await;
    assert_eq!(bound.code(), "FORBIDDEN", "{:?}", bound.body);
    let bound = put("/v1/oidc/clients/mine", Some(&plain)).await;
    assert_eq!(bound.status, StatusCode::OK, "{:?}", bound.body);
    let rebound = put("/v1/oidc/clients/mine", Some(&robot)).await;
    assert_eq!(rebound.code(), "FORBIDDEN", "{:?}", rebound.body);
    let secret = "/v1/oidc/clients/mine/secret";
    let issued = as_operator(&app, &clients, Method::POST, secret, None).await;
    assert_eq!(issued.status, StatusCode::OK, "{:?}", issued.body);

    // A client someone else bound to the operator can't be given a new
    // secret, moved, rewritten or disabled.
    let theirs = "/v1/oidc/clients/theirs";
    let bound = app
        .control(Method::PUT, theirs, Some(client(Some(&robot))))
        .await;
    assert_eq!(bound.status, StatusCode::OK, "{:?}", bound.body);
    let secret = "/v1/oidc/clients/theirs/secret";
    let issued = as_operator(&app, &clients, Method::POST, secret, None).await;
    assert_eq!(issued.code(), "FORBIDDEN", "{:?}", issued.body);
    for subject in [Some(plain.as_str()), Some(robot.as_str()), None] {
        let moved = put(theirs, subject).await;
        assert_eq!(moved.code(), "FORBIDDEN", "{:?}", moved.body);
    }
    let disabled = as_operator(&app, &clients, Method::DELETE, theirs, None).await;
    assert_eq!(disabled.code(), "FORBIDDEN", "{:?}", disabled.body);
    let issued = app.control(Method::POST, secret, None).await;
    assert_eq!(issued.status, StatusCode::OK, "{:?}", issued.body);
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

/// The harness checks control-plane responses against the API document, so
/// a body of the wrong shape fails the test that receives it.
// r[verify item.api.responses]
#[test]
fn responses_that_differ_from_the_api_document_fail() {
    let tenant = json!({"id": "not-a-uuid", "name": 7});
    let checked = std::panic::catch_unwind(|| {
        common::openapi::check(&Method::GET, "/v1/tenants/root", StatusCode::OK, &tenant);
    });
    assert!(checked.is_err(), "a malformed tenant passed the check");

    let undocumented = std::panic::catch_unwind(|| {
        common::openapi::check(
            &Method::GET,
            "/v1/tenants/root",
            StatusCode::CREATED,
            &json!({}),
        );
    });
    assert!(
        undocumented.is_err(),
        "an undocumented status passed the check"
    );

    let error = json!({"error": {"code": "NOT_FOUND", "message": "tenant not found"}});
    common::openapi::check(
        &Method::GET,
        "/v1/tenants/root?x=1",
        StatusCode::NOT_FOUND,
        &error,
    );
}
