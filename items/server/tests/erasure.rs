mod common;

use axum::http::{Method, StatusCode};
use common::{Reply, TestApp};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

async fn erase(app: &TestApp, subject: &str) -> Reply {
    app.control(Method::POST, &format!("/v1/subjects/{subject}/erase"), None)
        .await
}

/// A human operator holding `capabilities` through a global role: their
/// subject id and access token.
async fn operator(app: &TestApp, email: &str, capabilities: &[&str]) -> (String, String) {
    let subject = app.human(email, PASSWORD).await;
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
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": role})),
        )
        .await;
    assert!(assigned.status.is_success(), "{:?}", assigned.body);
    let token = app.login(email, PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (subject, token)
}

async fn erase_as(app: &TestApp, token: &str, subject: &str) -> Reply {
    let auth = format!("Bearer {token}");
    app.send(
        Method::POST,
        &format!("/v1/subjects/{subject}/erase"),
        &[("authorization", &auth)],
        None,
    )
    .await
}

// r[verify subject.erasure.operation]
// r[verify subject.erasure.idempotent]
// r[verify subject.erasure.tombstone]
#[tokio::test(flavor = "multi_thread")]
async fn erasing_a_subject_leaves_only_the_erased_subject() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;

    let erased = erase(&app, &ada).await;

    assert_eq!(erased.status, StatusCode::OK, "{:?}", erased.body);
    assert_eq!(erased.body["id"], ada);
    assert_eq!(erased.body["kind"], "human");
    assert_eq!(erased.body["state"], "erased");
    assert!(erased.body["erased_at"].is_string());
    assert!(erased.body["cursor"].is_u64(), "{:?}", erased.body);

    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{ada}"), None)
        .await;
    assert_eq!(detail.body["state"], "erased");
    assert_eq!(detail.body["erased_at"], erased.body["erased_at"]);
    assert_eq!(detail.body["credentials"], json!([]));
    assert_eq!(detail.body["mfa_factors"], json!([]));
    let found = app
        .control(Method::GET, "/v1/subjects?identifier=ada@example.com", None)
        .await;
    assert_eq!(found.body["subjects"], json!([]), "{:?}", found.body);

    let again = erase(&app, &ada).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.body["erased_at"], erased.body["erased_at"]);
    assert!(again.body["cursor"].is_null(), "{:?}", again.body);

    let unknown = erase(&app, &uuid::Uuid::now_v7().to_string()).await;
    assert_eq!(unknown.code(), "NOT_FOUND");
}

// r[verify subject.erasure.identifier-released]
// r[verify subject.erasure.removes]
#[tokio::test(flavor = "multi_thread")]
async fn an_erased_person_is_signed_out_and_looks_like_a_stranger() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    let login = app.login("ada@example.com", PASSWORD).await;
    let access = login.body["access_token"].as_str().unwrap().to_owned();
    let refresh = login.body["refresh_token"].as_str().unwrap().to_owned();

    assert_eq!(erase(&app, &ada).await.status, StatusCode::OK);

    let stale = app
        .with_bearer(Method::POST, "/v1/sign-out/others", &access)
        .await;
    assert_eq!(stale.code(), "SESSION_ENDED");
    let refreshed = app
        .post("/v1/refresh", json!({"refresh_token": refresh}))
        .await;
    assert_eq!(refreshed.status, StatusCode::UNAUTHORIZED);

    // Every way in answers exactly as it does for an identifier Konklav
    // has never seen.
    let erased = app.login("ada@example.com", PASSWORD).await;
    let stranger = app.login("stranger@example.com", PASSWORD).await;
    assert_eq!(erased.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        (erased.status, &erased.body),
        (stranger.status, &stranger.body)
    );
    for (uri, field) in [
        ("/v1/login/email-link/start", "email"),
        ("/v1/password-reset/start", "identifier"),
    ] {
        let erased = app.post(uri, json!({field: "ada@example.com"})).await;
        let stranger = app.post(uri, json!({field: "stranger@example.com"})).await;
        assert_eq!(
            (erased.status, &erased.body),
            (stranger.status, &stranger.body),
            "{uri}"
        );
    }

    // The identifier is free: the person can come back as someone new.
    let returned = app.human("ada@example.com", PASSWORD).await;
    assert_ne!(returned, ada);
    assert_eq!(
        app.login("ada@example.com", PASSWORD).await.status,
        StatusCode::OK
    );
}

// r[verify subject.erasure.blocks-writes]
// r[verify subject.state]
// r[verify import.idempotent]
#[tokio::test(flavor = "multi_thread")]
async fn every_write_to_an_erased_subject_answers_subject_erased() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    let tenant = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        Some(json!({})),
    )
    .await;
    assert_eq!(erase(&app, &ada).await.status, StatusCode::OK);

    let attempts: [(Method, String, Option<Value>); 8] = [
        (
            Method::PUT,
            format!("/v1/subjects/{ada}"),
            Some(json!({"kind": "human"})),
        ),
        (Method::POST, format!("/v1/subjects/{ada}/enable"), None),
        (Method::POST, format!("/v1/subjects/{ada}/disable"), None),
        (
            Method::POST,
            format!("/v1/subjects/{ada}/credentials"),
            Some(
                json!({"kind": "password", "identifier": "back@example.com", "password": PASSWORD}),
            ),
        ),
        (
            Method::PUT,
            format!("/v1/memberships/{}", uuid::Uuid::now_v7()),
            Some(json!({"subject": ada, "tenant": tenant})),
        ),
        (
            Method::POST,
            format!("/v1/subjects/{ada}/global-assignments"),
            Some(json!({"role": "konklav.admin"})),
        ),
        (
            Method::POST,
            "/v1/import/subjects".to_owned(),
            Some(json!({"subjects": [{"id": ada, "kind": "human"}]})),
        ),
        (
            Method::POST,
            "/v1/batch".to_owned(),
            Some(json!({"operations": [
                {"method": "POST", "path": format!("/subjects/{ada}/enable")},
            ]})),
        ),
    ];
    for (method, uri, body) in attempts {
        let reply = app.control(method.clone(), &uri, body).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{method} {uri}");
        assert_eq!(
            reply.code(),
            "SUBJECT_ERASED",
            "{method} {uri}: {:?}",
            reply.body
        );
    }

    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{ada}"), None)
        .await;
    assert_eq!(detail.body["state"], "erased");
    assert_eq!(detail.body["credentials"], json!([]));
}

// r[verify subject.erasure.operation]
// r[verify authz.control-plane.escalation]
#[tokio::test(flavor = "multi_thread")]
async fn erasing_needs_its_own_capability_and_more_for_an_operator() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    let (_, people) = operator(&app, "people@example.com", &["konklav:subjects:manage"]).await;
    let (eraser_id, eraser) =
        operator(&app, "eraser@example.com", &["konklav:subjects:erase"]).await;
    let (root_id, root) = operator(&app, "root@example.com", &["konklav:control:all"]).await;

    // Managing subjects is not enough.
    let refused = erase_as(&app, &people, &ada).await;
    assert_eq!(refused.code(), "FORBIDDEN", "{:?}", refused.body);

    // The capability erases ordinary subjects, but not operators.
    let over_operator = erase_as(&app, &eraser, &root_id).await;
    assert_eq!(
        over_operator.code(),
        "FORBIDDEN",
        "{:?}",
        over_operator.body
    );
    assert_eq!(erase_as(&app, &eraser, &ada).await.status, StatusCode::OK);

    // Nobody erases themself, whatever they hold.
    for (own, token) in [(&eraser_id, &eraser), (&root_id, &root)] {
        let reply = erase_as(&app, token, own).await;
        assert_eq!(reply.code(), "FORBIDDEN", "{:?}", reply.body);
    }

    // `konklav:control:all` erases an operator.
    assert_eq!(
        erase_as(&app, &root, &eraser_id).await.status,
        StatusCode::OK
    );
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{root_id}"), None)
        .await;
    assert_eq!(detail.body["state"], "active");
}

// r[verify subject.erasure.atomic]
// r[verify platform.batch.atomic]
#[tokio::test(flavor = "multi_thread")]
async fn an_erasure_in_a_batch_commits_or_fails_with_the_batch() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;

    let failed = app
        .control(
            Method::POST,
            "/v1/batch",
            Some(json!({"operations": [
                {"method": "POST", "path": format!("/subjects/{ada}/erase")},
                {"method": "POST", "path": format!("/subjects/{}/disable", uuid::Uuid::now_v7())},
            ]})),
        )
        .await;
    assert_eq!(failed.code(), "NOT_FOUND", "{:?}", failed.body);
    assert_eq!(failed.body["error"]["operation"], 1);
    assert_eq!(
        app.login("ada@example.com", PASSWORD).await.status,
        StatusCode::OK,
        "the failed batch erased nothing"
    );

    let applied = app
        .control(
            Method::POST,
            "/v1/batch",
            Some(json!({"operations": [
                {"method": "POST", "path": format!("/subjects/{ada}/erase")},
            ]})),
        )
        .await;
    assert_eq!(applied.status, StatusCode::OK, "{:?}", applied.body);
    assert_eq!(applied.body["results"][0]["body"]["state"], "erased");
    assert_eq!(
        app.login("ada@example.com", PASSWORD).await.status,
        StatusCode::UNAUTHORIZED
    );
}

// r[verify subject.erasure.event]
// r[verify feed.subject-erased]
// r[verify feed.kinds]
#[tokio::test(flavor = "multi_thread")]
async fn relying_systems_read_the_erasure_on_the_feed() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    app.login("ada@example.com", PASSWORD).await;
    let consumer = app.service_token().await;

    let erased = erase(&app, &ada).await;

    let feed = app
        .with_bearer(
            Method::GET,
            "/v1/events/batch?after=0&limit=1000",
            &consumer,
        )
        .await;
    assert_eq!(feed.status, StatusCode::OK, "{:?}", feed.body);
    let events = feed.body["events"].as_array().unwrap();
    let position = |kind: &str| {
        events
            .iter()
            .rposition(|e| e["kind"] == kind && e["payload"].to_string().contains(&ada))
    };
    let erasure = position("subject.erased").expect("a subject.erased event");
    assert_eq!(events[erasure]["cursor"], erased.body["cursor"]);
    assert_eq!(
        events[erasure]["payload"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["erased_at", "subject"]
    );
    assert!(position("session.changed").unwrap() < erasure);
    assert!(position("entitlements.changed").unwrap() < erasure);

    let only = app
        .with_bearer(
            Method::GET,
            "/v1/events/batch?after=0&limit=1000&kinds=subject.erased",
            &consumer,
        )
        .await;
    assert_eq!(only.body["events"].as_array().unwrap().len(), 1);
}

// r[verify subject.erasure.bound-client]
#[tokio::test(flavor = "multi_thread")]
async fn a_service_principal_behind_a_client_is_erased_only_once_the_client_is_disabled() {
    let app = TestApp::new().await;
    let service = uuid::Uuid::now_v7().to_string();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{service}"),
        Some(json!({"kind": "service"})),
    )
    .await;
    let client = json!({
        "kind": "confidential",
        "redirect_uris": ["https://reports.example/callback"],
        "audience": "reports",
        "service_subject": service,
    });
    let put = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/reports",
            Some(client.clone()),
        )
        .await;
    assert!(put.status.is_success(), "{:?}", put.body);

    let refused = erase(&app, &service).await;
    assert_eq!(refused.code(), "CONFLICT", "{:?}", refused.body);

    let disabled = app
        .control(Method::DELETE, "/v1/oidc/clients/reports", None)
        .await;
    assert!(disabled.status.is_success(), "{:?}", disabled.body);
    assert_eq!(erase(&app, &service).await.status, StatusCode::OK);

    let enabled = app
        .control(Method::PUT, "/v1/oidc/clients/reports", Some(client))
        .await;
    assert_eq!(enabled.code(), "SUBJECT_ERASED", "{:?}", enabled.body);
}
