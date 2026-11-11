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

async fn erased_page(app: &TestApp, token: &str, query: &str) -> Reply {
    let reply = app
        .with_bearer(Method::GET, &format!("/v1/erased-subjects{query}"), token)
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    reply
}

fn listed(page: &Reply) -> Vec<String> {
    page.body["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["subject"].as_str().unwrap().to_owned())
        .collect()
}

// r[verify subject.erasure.list]
#[tokio::test(flavor = "multi_thread")]
async fn relying_systems_page_through_every_erasure_in_order() {
    let app = TestApp::new().await;
    let consumer = app.service_token().await;
    let first = app.human("first@example.com", PASSWORD).await;
    let kept = app.human("kept@example.com", PASSWORD).await;
    // The two in the batch are erased at the same instant, so paging has to
    // tell them apart by more than the time.
    let mut together = [
        app.human("second@example.com", PASSWORD).await,
        app.human("third@example.com", PASSWORD).await,
    ];
    together.sort();
    let last = app.human("last@example.com", PASSWORD).await;

    assert_eq!(
        erased_page(&app, &consumer, "").await.body["subjects"],
        json!([])
    );

    let before = chrono::Utc::now().timestamp();
    assert_eq!(erase(&app, &first).await.status, StatusCode::OK);
    let batch = app
        .control(
            Method::POST,
            "/v1/batch",
            Some(json!({"operations": [
                {"method": "POST", "path": format!("/subjects/{}/erase", together[1])},
                {"method": "POST", "path": format!("/subjects/{}/erase", together[0])},
            ]})),
        )
        .await;
    assert_eq!(batch.status, StatusCode::OK, "{:?}", batch.body);
    assert_eq!(erase(&app, &last).await.status, StatusCode::OK);
    let order = [
        first.clone(),
        together[0].clone(),
        together[1].clone(),
        last.clone(),
    ];

    let all = erased_page(&app, &consumer, "").await;
    assert_eq!(listed(&all), order);
    assert!(all.body["next"].is_null(), "{:?}", all.body);
    assert!(!listed(&all).contains(&kept));
    let entry = &all.body["subjects"][1];
    assert_eq!(
        entry.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["erased_at", "subject"],
        "the same form as a subject.erased event's payload"
    );
    assert_eq!(entry["erased_at"], all.body["subjects"][2]["erased_at"]);
    assert!(entry["erased_at"].as_i64().unwrap() >= before);

    // One at a time, each page starting behind the last subject of the one
    // before.
    let mut paged = Vec::new();
    let mut query = "?limit=1".to_owned();
    loop {
        let page = erased_page(&app, &consumer, &query).await;
        paged.extend(listed(&page));
        match page.body["next"].as_str() {
            Some(next) => query = format!("?limit=1&after={next}"),
            None => break,
        }
    }
    assert_eq!(paged, order);

    // `since` is inclusive, and leaves out what was erased earlier.
    let since = erased_page(&app, &consumer, &format!("?since={before}")).await;
    assert_eq!(listed(&since), order);
    let later = chrono::Utc::now().timestamp() + 60;
    let none = erased_page(&app, &consumer, &format!("?since={later}")).await;
    assert_eq!(none.body, json!({"subjects": [], "next": null}));

    // A subject that isn't erased marks no position.
    let stray = app
        .with_bearer(
            Method::GET,
            &format!("/v1/erased-subjects?after={kept}"),
            &consumer,
        )
        .await;
    assert_eq!(stray.code(), "INVALID_REQUEST", "{:?}", stray.body);

    // Like the rest of the relying surface, only for service principals.
    let human = app.login("kept@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let forbidden = app
        .with_bearer(Method::GET, "/v1/erased-subjects", &human)
        .await;
    assert_eq!(forbidden.code(), "FORBIDDEN");
    let anonymous = app
        .send(Method::GET, "/v1/erased-subjects", &[], None)
        .await;
    assert_eq!(anonymous.code(), "UNAUTHENTICATED");
}

/// An app with a catalog, a `reader` template allowing `project:read`,
/// and a tenant with a role from it: the app and the tenant's id.
async fn app_with_a_tenant() -> (TestApp, String) {
    let app = TestApp::new().await;
    let catalog = app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({
                "actions": [{"name": "project:read"}],
                "groups": [],
                "scope_kinds": [],
                "facts": [],
                "session_flags": []
            })),
        )
        .await;
    assert_eq!(catalog.status, StatusCode::OK, "{:?}", catalog.body);
    app.control(
        Method::PUT,
        "/v1/templates/reader",
        Some(json!({"policies": [{"action": "project:read", "effect": "allow"}]})),
    )
    .await;
    let tenant = uuid::Uuid::now_v7().to_string();
    let created = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({"templates": ["reader"]})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    (app, tenant)
}

// r[verify subject.erasure.entitlements]
#[tokio::test(flavor = "multi_thread")]
async fn the_relying_surface_answers_for_an_erased_subject_as_for_one_holding_nothing() {
    let (app, tenant) = app_with_a_tenant().await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    let idle = app.human("idle@example.com", PASSWORD).await;
    let membership = uuid::Uuid::now_v7();
    let joined = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": ada, "tenant": tenant})),
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

    let identity = app.login("ada@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
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

    let consumer = app.service_token().await;
    let service = format!("Bearer {consumer}");
    let check = async || {
        let reply = app
            .send(
                Method::POST,
                "/v1/check",
                &[("authorization", &service)],
                Some(json!({"token": token, "requirements": {"tenant": ["project:read"]}})),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        reply.body
    };
    let entitlements = async |subject: &str, tenant: Option<&str>| {
        let uri = match tenant {
            Some(tenant) => format!("/v1/entitlements/{subject}/{tenant}"),
            None => format!("/v1/entitlements/{subject}"),
        };
        let mut reply = app.with_bearer(Method::GET, &uri, &consumer).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let set = reply.body.as_object_mut().unwrap();
        set.remove("subject_id");
        set.remove("revision");
        reply.body
    };
    assert_eq!(check().await["decision"], "allow");
    assert_eq!(
        entitlements(&ada, Some(&tenant)).await["tenant"],
        json!(["project:read"])
    );

    assert_eq!(erase(&app, &ada).await.status, StatusCode::OK);

    assert_eq!(
        check().await,
        json!({"decision": "deny", "reason": "invalid_token", "revision": null})
    );
    for scope in [Some(tenant.as_str()), None] {
        let erased = entitlements(&ada, scope).await;
        assert_eq!(erased, entitlements(&idle, scope).await, "{scope:?}");
        assert_eq!(erased["tenant"], json!([]), "{erased:?}");
    }
}

async fn personal_data(app: &TestApp, subject: &str) -> Reply {
    app.control(
        Method::GET,
        &format!("/v1/subjects/{subject}/personal-data"),
        None,
    )
    .await
}

/// What [`held_by_ada`] seeded.
struct Held {
    ada: String,
    grace: String,
    membership: String,
    refresh_token: String,
}

/// Seeds Ada with a password, two MFA factors, a membership with a role, a
/// session, a pending challenge and a failed and a successful login, and
/// Grace with a session of her own.
async fn held_by_ada(app: &TestApp, tenant: &str) -> Held {
    use konklav_store::challenges::{self, NewChallenge, Purpose};
    use konklav_store::mfa::{self, EmailCodeData, FactorData, TotpData};

    let ada = app.human("ada@example.com", PASSWORD).await;
    let grace = app.human("grace@example.com", PASSWORD).await;
    let membership = uuid::Uuid::now_v7().to_string();
    let joined = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": ada, "tenant": tenant})),
        )
        .await;
    assert!(joined.status.is_success(), "{:?}", joined.body);
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/memberships/{membership}/assignments"),
            Some(json!({"role": "reader"})),
        )
        .await;
    assert!(assigned.status.is_success(), "{:?}", assigned.body);
    let wrong = app.login("ada@example.com", "not the password").await;
    assert!(!wrong.status.is_success());
    let login = app.login("ada@example.com", PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    app.login("grace@example.com", PASSWORD).await;
    {
        let mut conn = app.db.pool().get().await.unwrap();
        let subject: konklav_core::SubjectId = ada.parse().unwrap();
        mfa::create(
            &mut conn,
            subject,
            &FactorData::EmailCode(EmailCodeData {
                email: "ada@codes.example".into(),
            }),
        )
        .await
        .unwrap();
        mfa::create(
            &mut conn,
            subject,
            &FactorData::Totp(TotpData {
                key_id: "seed-key".into(),
                nonce: "seed-nonce".into(),
                ciphertext: "seed-ciphertext".into(),
                last_step: None,
            }),
        )
        .await
        .unwrap();
        challenges::create(
            &mut conn,
            NewChallenge {
                id: uuid::Uuid::now_v7(),
                purpose: Purpose::EmailLink,
                subject_id: Some(subject),
                credential_id: None,
                mfa_factor_id: None,
                session_id: None,
                recipient: "ada@example.com".into(),
                secret_hash: b"challenge-secret".to_vec(),
                details: json!({"nonce": "challenge-material"}),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            },
        )
        .await
        .unwrap();
    }
    Held {
        ada,
        grace,
        membership,
        refresh_token: login.body["refresh_token"].as_str().unwrap().to_owned(),
    }
}

// r[verify subject.report.contents]
// r[verify subject.report.no-secrets]
// r[verify subject.report.erased]
#[tokio::test(flavor = "multi_thread")]
async fn the_personal_data_report_shows_what_is_held_without_secrets() {
    let (app, tenant) = app_with_a_tenant().await;
    let Held {
        ada,
        grace,
        membership,
        refresh_token,
    } = held_by_ada(&app, &tenant).await;

    let report = personal_data(&app, &ada).await;
    assert_eq!(report.status, StatusCode::OK, "{:?}", report.body);
    let body = &report.body;
    assert_eq!(body["subject"]["id"], ada);
    assert_eq!(body["subject"]["state"], "active");

    let credentials = body["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), 1, "{credentials:?}");
    assert_eq!(credentials[0]["kind"], "password");
    assert_eq!(credentials[0]["identifier"], "ada@example.com");

    let factors = body["mfa_factors"].as_array().unwrap();
    assert_eq!(factors.len(), 2, "{factors:?}");
    assert_eq!(factors[0]["email"], "ada@codes.example");
    assert_eq!(factors[1]["kind"], "totp");

    assert_eq!(body["memberships"][0]["id"], membership);
    assert_eq!(body["memberships"][0]["tenant_id"], tenant);
    assert_eq!(body["role_assignments"][0]["target"]["id"], membership);

    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0]["subject_id"], ada);
    assert_eq!(sessions[0]["amr"], json!(["pwd"]));

    assert_eq!(body["challenges"][0]["purpose"], "email_link");
    assert_eq!(body["challenges"][0]["recipient"], "ada@example.com");
    assert!(body["challenges"][0]["created_at"].is_string());

    let attempts = body["login_attempts"].as_array().unwrap();
    let outcomes: Vec<bool> = attempts
        .iter()
        .map(|a| a["succeeded"].as_bool().unwrap())
        .collect();
    assert_eq!(outcomes, [false, true], "{attempts:?}");
    assert_eq!(attempts[0]["identifier"], "ada@example.com");
    assert_eq!(attempts[0]["kind"], "password");

    // No secret, under any name, and nothing of anyone else's.
    let text = body.to_string();
    for secret in [
        "$argon2",
        "hash",
        "seed-",
        "ciphertext",
        "challenge-secret",
        "challenge-material",
        "details",
        "grace@example.com",
        grace.as_str(),
    ] {
        assert!(!text.contains(secret), "{secret} in the report: {text}");
    }
    assert!(!text.contains(&refresh_token));

    assert_eq!(erase(&app, &ada).await.status, StatusCode::OK);
    let report = personal_data(&app, &ada).await;
    assert_eq!(report.status, StatusCode::OK, "{:?}", report.body);
    assert_eq!(report.body["subject"]["state"], "erased");
    assert!(report.body["subject"]["erased_at"].is_string());
    for list in [
        "credentials",
        "mfa_factors",
        "memberships",
        "role_assignments",
        "sessions",
        "challenges",
        "login_attempts",
    ] {
        assert_eq!(report.body[list], json!([]), "{list}");
    }

    let unknown = personal_data(&app, &uuid::Uuid::now_v7().to_string()).await;
    assert_eq!(unknown.code(), "NOT_FOUND");
}

// r[verify subject.report.contents]
#[tokio::test(flavor = "multi_thread")]
async fn the_personal_data_report_needs_the_capability_to_manage_subjects() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    let (_, manager) = operator(&app, "manager@example.com", &["konklav:subjects:manage"]).await;
    let (_, eraser) = operator(&app, "eraser@example.com", &["konklav:subjects:erase"]).await;
    let path = format!("/v1/subjects/{ada}/personal-data");

    let read = app.with_bearer(Method::GET, &path, &manager).await;
    assert_eq!(read.status, StatusCode::OK, "{:?}", read.body);
    assert_eq!(read.body["credentials"][0]["identifier"], "ada@example.com");

    let refused = app.with_bearer(Method::GET, &path, &eraser).await;
    assert_eq!(refused.code(), "FORBIDDEN");
    let anonymous = app.send(Method::GET, &path, &[], None).await;
    assert_eq!(anonymous.code(), "UNAUTHENTICATED");
}

// r[verify subject.report.contents]
// r[verify subject.report.no-secrets]
#[tokio::test(flavor = "multi_thread")]
async fn a_service_principals_report_shows_its_keys_and_workload_without_secrets() {
    let app = TestApp::new().await;
    let service = uuid::Uuid::now_v7().to_string();
    let created = app
        .control(
            Method::PUT,
            &format!("/v1/subjects/{service}"),
            Some(json!({"kind": "service"})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let credentials = format!("/v1/subjects/{service}/credentials");
    let key = app
        .control(
            Method::POST,
            &credentials,
            Some(json!({"kind": "secret_key"})),
        )
        .await;
    assert!(key.status.is_success(), "{:?}", key.body);
    // Straight into the store: the control plane takes only providers that
    // are configured.
    {
        use konklav_store::credentials::{self, CredentialData, FederatedData, NewCredential};
        let mut conn = app.db.pool().get().await.unwrap();
        credentials::insert(
            &mut conn,
            NewCredential {
                id: konklav_core::CredentialId::new_v7(),
                subject_id: service.parse().unwrap(),
                identifier: credentials::federated_identifier("upstream", "Workload-7"),
                data: CredentialData::Federated(FederatedData {
                    provider: "upstream".into(),
                    subject: "Workload-7".into(),
                    email: Some("workload@upstream.example".into()),
                    email_verified: Some(true),
                }),
                mfa_factors_required: 0,
                replaces: None,
            },
        )
        .await
        .unwrap();
    }

    let report = personal_data(&app, &service).await;
    assert_eq!(report.status, StatusCode::OK, "{:?}", report.body);
    let listed = report.body["credentials"].as_array().unwrap();
    assert_eq!(listed[0]["kind"], "secret_key");
    assert!(listed[0]["slots"]["a"]["created_at"].is_string());
    assert_eq!(listed[1]["kind"], "federated");
    assert_eq!(
        listed[1]["federated"],
        json!({
            "provider": "upstream",
            "subject": "Workload-7",
            "email": "workload@upstream.example",
            "email_verified": true
        })
    );

    let text = report.body.to_string();
    for slot in ["a", "b"] {
        let shown = key.body["secret_keys"][slot].as_str().unwrap();
        let secret = shown.split_once('.').unwrap().1;
        assert!(!text.contains(secret), "slot {slot}'s secret in the report");
    }
    assert!(!text.contains("hash"), "{text}");
}
