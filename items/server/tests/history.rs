#![allow(clippy::too_many_lines)]

//! History: explaining decisions as of a past time, and how long history
//! reaches back.

mod common;

use axum::http::{Method, StatusCode};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use common::TestApp;
use diesel_async::RunQueryDsl;
use konklav_server::sweeper::{self, Settings};
use konklav_store::history;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

struct World {
    app: TestApp,
    tenant: String,
    subject: String,
    membership: String,
}

/// A member holding `reader` (allows `document:read` tenant-wide).
async fn world() -> World {
    let app = TestApp::new().await;
    let reply = app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({"actions": [{"name": "document:read"}]})),
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
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}/roles/reader"),
            Some(json!({"policies": [{"action": "document:read", "effect": "allow"}]})),
        )
        .await;
    assert!(reply.status.is_success(), "{:?}", reply.body);
    let email = format!("{}@example.com", uuid::Uuid::now_v7().simple());
    let subject = app.human(&email, PASSWORD).await;
    let membership = uuid::Uuid::now_v7().to_string();
    app.control(
        Method::PUT,
        &format!("/v1/memberships/{membership}"),
        Some(json!({"subject": subject, "tenant": tenant})),
    )
    .await;
    let reply = app
        .control(
            Method::POST,
            &format!("/v1/memberships/{membership}/assignments"),
            Some(json!({"role": "reader"})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    World {
        app,
        tenant,
        subject,
        membership,
    }
}

async fn configure(app: &TestApp, retention: Option<Duration>) {
    let mut conn = app.db.pool().get().await.unwrap();
    history::configure(&mut conn, retention).await.unwrap();
}

/// A moment strictly between the writes before and after it, which are
/// timed by their transactions.
async fn moment() -> DateTime<Utc> {
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let at = Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    at
}

fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Micros, true)
}

async fn explain(world: &World, at: Option<DateTime<Utc>>) -> common::Reply {
    let mut body = json!({"tenant": world.tenant, "requirements": {"tenant": ["document:read"]}});
    if let Some(at) = at {
        body["at"] = Value::String(rfc3339(at));
    }
    world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/explain-decision", world.subject),
            Some(body),
        )
        .await
}

fn check<'a>(explained: &'a common::Reply, name: &str) -> &'a Value {
    explained.body["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["check"] == name)
        .unwrap_or_else(|| panic!("no {name} check in {:?}", explained.body))
}

async fn count(app: &TestApp, sql: &str) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = app.db.pool().get().await.unwrap();
    diesel::sql_query(format!("select count(*) as count from {sql}"))
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

// r[verify history.record]
// r[verify history.as-of]
// r[verify authz.explain.at]
#[tokio::test(flavor = "multi_thread")]
async fn decisions_are_explained_as_they_were() {
    let world = world().await;
    let before_history = moment().await;
    configure(&world.app, Some(Duration::days(30))).await;
    let assigned = moment().await;

    // Removing the assignment deletes its row, and deleting the role its
    // policies with it.
    let detail = world
        .app
        .control(
            Method::GET,
            &format!("/v1/memberships/{}", world.membership),
            None,
        )
        .await;
    let assignment = detail.body["assignments"][0]["id"].as_str().unwrap();
    let removed = world
        .app
        .control(
            Method::DELETE,
            &format!("/v1/assignments/{assignment}"),
            None,
        )
        .await;
    assert_eq!(removed.body["deleted"], true, "{:?}", removed.body);
    let unassigned = moment().await;
    let deleted = world
        .app
        .control(
            Method::DELETE,
            &format!("/v1/tenants/{}/roles/reader", world.tenant),
            None,
        )
        .await;
    assert!(deleted.status.is_success(), "{:?}", deleted.body);
    // Ending the membership only changes its state.
    let ended = world
        .app
        .control(
            Method::POST,
            &format!("/v1/memberships/{}/end", world.membership),
            None,
        )
        .await;
    assert!(ended.status.is_success(), "{:?}", ended.body);

    let now = explain(&world, None).await;
    assert_eq!(now.status, StatusCode::OK, "{:?}", now.body);
    assert_eq!(now.body["allowed"], false);
    assert_eq!(check(&now, "membership_active")["passed"], false);

    let then = explain(&world, Some(assigned)).await;
    assert_eq!(then.status, StatusCode::OK, "{:?}", then.body);
    assert_eq!(then.body["allowed"], true, "{:?}", then.body);
    assert_eq!(check(&then, "membership_active")["passed"], true);
    assert!(
        then.body["actions"][0]["message"]
            .as_str()
            .unwrap()
            .starts_with("Allowed: `reader ("),
        "{:?}",
        then.body
    );

    let between = explain(&world, Some(unassigned)).await;
    assert_eq!(between.status, StatusCode::OK, "{:?}", between.body);
    assert_eq!(between.body["allowed"], false);
    assert_eq!(check(&between, "membership_active")["passed"], true);

    // Reading the past leaves the present alone.
    assert_eq!(explain(&world, None).await.body, now.body);

    for (at, refusal) in [
        (before_history, "history reaches back only to"),
        (Utc::now() + Duration::hours(1), "`at` is in the future"),
    ] {
        let refused = explain(&world, Some(at)).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{:?}",
            refused.body
        );
        let message = refused.body["error"]["message"].as_str().unwrap();
        assert!(message.starts_with(refusal), "{message}");
    }
    let with_session = world
        .app
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/explain-decision", world.subject),
            Some(json!({
                "tenant": world.tenant,
                "session": uuid::Uuid::now_v7(),
                "at": rfc3339(assigned),
            })),
        )
        .await;
    assert_eq!(with_session.status, StatusCode::BAD_REQUEST);
}

// r[verify history.disabled]
#[tokio::test(flavor = "multi_thread")]
async fn history_is_off_unless_enabled_and_discarded_when_disabled() {
    let world = world().await;
    let at = moment().await;
    let refused = explain(&world, Some(at)).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
    assert!(
        refused.body["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("history isn't enabled"),
        "{:?}",
        refused.body
    );
    assert_eq!(
        count(&world.app, "row_version").await,
        0,
        "nothing recorded"
    );

    configure(&world.app, Some(Duration::days(30))).await;
    let versions = count(&world.app, "row_version").await;
    assert!(versions > 0, "current rows are copied when enabled");
    // Enabling again only changes the retention.
    configure(&world.app, Some(Duration::days(7))).await;
    assert_eq!(count(&world.app, "row_version").await, versions);
    let mut conn = world.app.db.pool().get().await.unwrap();
    let status = history::status(&mut conn).await.unwrap().unwrap();
    assert_eq!(status.retention, Duration::days(7));
    drop(conn);
    let at = moment().await;
    assert_eq!(explain(&world, Some(at)).await.status, StatusCode::OK);

    configure(&world.app, None).await;
    assert_eq!(count(&world.app, "row_version").await, 0);
    let refused = explain(&world, Some(at)).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
}

// r[verify retention.history]
#[tokio::test(flavor = "multi_thread")]
async fn versions_go_once_retention_has_passed_since_they_ended() {
    let world = world().await;
    configure(&world.app, Some(Duration::days(30))).await;
    let reply = world
        .app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{}/facts", world.tenant),
            Some(json!({})),
        )
        .await;
    assert!(reply.status.is_success(), "{:?}", reply.body);
    for state in ["suspended", "active"] {
        let reply = world
            .app
            .control(
                Method::PUT,
                &format!("/v1/tenants/{}/state", world.tenant),
                Some(json!({"state": state})),
            )
            .await;
        assert!(reply.status.is_success(), "{:?}", reply.body);
    }
    let of_tenant = format!(
        "relation = 'tenant'::regclass and key = '{{\"id\": \"{}\"}}'",
        world.tenant
    );
    let tenant_versions = format!("row_version where {of_tenant}");
    let ended = format!("{tenant_versions} and valid_until is not null");
    let ended_count = count(&world.app, &ended).await;
    assert!(ended_count >= 2, "{ended_count}");
    // Two of them ended long ago, the current one began long ago.
    let mut conn = world.app.db.pool().get().await.unwrap();
    diesel::sql_query(format!(
        "update row_version set valid_from = now() - interval '90 days',
             valid_until = case when valid_until is null then null else now() - interval '40 days' end
         where {of_tenant}"
    ))
    .execute(&mut conn)
    .await
    .unwrap();

    let swept = sweeper::sweep(
        &mut conn,
        Settings {
            sessions: Duration::days(30),
            events: Duration::days(7),
            interval: std::time::Duration::from_secs(300),
            batch: 1,
        },
        Utc::now(),
    )
    .await
    .unwrap()
    .expect("nothing else holds the lock");
    assert_eq!(
        swept.history,
        usize::try_from(ended_count).unwrap(),
        "{swept:?}"
    );
    assert_eq!(count(&world.app, &ended).await, 0);
    assert_eq!(
        count(&world.app, &tenant_versions).await,
        1,
        "the current version stays, however old"
    );
}

// r[verify history.record]
// r[verify authz.explain.at]
#[tokio::test(flavor = "multi_thread")]
async fn removed_registered_scopes_count_as_of_before_their_removal() {
    let world = world().await;
    let reply = world
        .app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({
                "actions": [{"name": "document:read"}],
                "scope_kinds": [{"name": "document", "registered": true}],
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    configure(&world.app, Some(Duration::days(30))).await;
    let recorded = world
        .app
        .control(
            Method::PUT,
            "/v1/registered-scopes/document/d-1",
            Some(json!({"tenant": world.tenant})),
        )
        .await;
    assert_eq!(recorded.status, StatusCode::OK, "{:?}", recorded.body);
    let registered = moment().await;
    let removed = world
        .app
        .control(Method::DELETE, "/v1/registered-scopes/document/d-1", None)
        .await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);

    let explain = async |at: Option<DateTime<Utc>>| {
        let mut body = json!({
            "tenant": world.tenant,
            "requirements": {"scopes": [{"kind": "document", "id": "d-1", "actions": ["document:read"]}]},
        });
        if let Some(at) = at {
            body["at"] = Value::String(rfc3339(at));
        }
        world
            .app
            .control(
                Method::POST,
                &format!("/v1/subjects/{}/explain-decision", world.subject),
                Some(body),
            )
            .await
    };
    let now = explain(None).await;
    assert_eq!(now.status, StatusCode::OK, "{:?}", now.body);
    assert_eq!(now.body["allowed"], false, "{:?}", now.body);
    let then = explain(Some(registered)).await;
    assert_eq!(then.status, StatusCode::OK, "{:?}", then.body);
    assert_eq!(then.body["allowed"], true, "{:?}", then.body);
}
