//! Access requests in the store: one pending per subject and tenant,
//! decided once, each change an event, withdrawn by erasure.

use konklav_core::{MembershipId, SubjectId, TenantId};
use konklav_store::access_requests::{self, AccessRequestState, Filter};
use konklav_store::subjects::{self, SubjectKind};
use konklav_store::tenants::{self, ROOT};
use konklav_store::{Connection, events, memberships};
use konklav_test_support::TestDatabase;
use serde_json::json;

async fn setup(conn: &mut Connection) -> (SubjectId, TenantId) {
    let tenant = TenantId::new_v7();
    tenants::create(conn, tenant, ROOT, &json!({}))
        .await
        .unwrap();
    let subject = SubjectId::new_v7();
    subjects::create(conn, subject, SubjectKind::Human)
        .await
        .unwrap();
    (subject, tenant)
}

/// The kinds and states of the events after `after`.
async fn changes(conn: &mut Connection, after: konklav_core::Cursor) -> Vec<String> {
    events::after(conn, after, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == access_requests::EVENT)
        .map(|event| event.payload["state"].as_str().unwrap().to_owned())
        .collect()
}

// r[verify membership.access-request]
// r[verify membership.access-request.decision]
// r[verify membership.access-request.event]
#[tokio::test(flavor = "multi_thread")]
async fn a_request_is_pending_once_and_decided_once() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (subject, tenant) = setup(&mut conn).await;
    let start = events::head(&mut conn).await.unwrap();

    let (first, created) =
        access_requests::create(&mut conn, uuid::Uuid::now_v7(), subject, tenant)
            .await
            .unwrap();
    assert!(created);
    assert!(first.is_pending());
    let (again, created) =
        access_requests::create(&mut conn, uuid::Uuid::now_v7(), subject, tenant)
            .await
            .unwrap();
    assert!(!created, "the pending one answers");
    assert_eq!(again.id, first.id);

    let membership = MembershipId::new_v7();
    memberships::create(&mut conn, membership, subject, tenant, &json!({}))
        .await
        .unwrap();
    let approved = access_requests::decide(
        &mut conn,
        first.id,
        AccessRequestState::Approved,
        Some(membership),
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(approved.membership_id, Some(membership));
    assert!(approved.decided_at.is_some());
    assert!(
        access_requests::decide(&mut conn, first.id, AccessRequestState::Denied, None, None)
            .await
            .unwrap()
            .is_none(),
        "decided already"
    );
    assert!(
        access_requests::decide(
            &mut conn,
            first.id,
            AccessRequestState::Approved,
            None,
            None
        )
        .await
        .is_ok_and(|decided| decided.is_none())
    );

    // Decided, so a new one may be pending.
    let (next, created) = access_requests::create(&mut conn, uuid::Uuid::now_v7(), subject, tenant)
        .await
        .unwrap();
    assert!(created);
    access_requests::decide(&mut conn, next.id, AccessRequestState::Denied, None, None)
        .await
        .unwrap()
        .unwrap();
    assert!(
        access_requests::last_denied(&mut conn, subject, tenant)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        changes(&mut conn, start).await,
        ["pending", "approved", "pending", "denied"]
    );
    let listed = access_requests::list(
        &mut conn,
        Filter {
            tenant: Some(tenant),
            ..Filter::default()
        },
        None,
        10,
    )
    .await
    .unwrap();
    assert_eq!(
        listed.iter().map(|r| r.id).collect::<Vec<_>>(),
        [next.id, first.id],
        "newest first"
    );
}

// r[verify membership.access-request.erasure]
#[tokio::test(flavor = "multi_thread")]
async fn erasure_withdraws_pending_requests() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (subject, tenant) = setup(&mut conn).await;
    let (request, _) = access_requests::create(&mut conn, uuid::Uuid::now_v7(), subject, tenant)
        .await
        .unwrap();
    subjects::erase(&mut conn, subject).await.unwrap();
    let withdrawn = access_requests::get(&mut conn, request.id).await.unwrap();
    assert_eq!(withdrawn.state, AccessRequestState::Withdrawn);
    assert!(
        access_requests::create(&mut conn, uuid::Uuid::now_v7(), subject, tenant)
            .await
            .is_err(),
        "nothing is asked for an erased subject"
    );
}
