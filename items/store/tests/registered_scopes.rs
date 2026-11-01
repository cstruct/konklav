use diesel_async::AsyncConnection;
use konklav_authz::Scope;
use konklav_core::{Cursor, MembershipId, SubjectId, TenantId};
use konklav_store::catalog::{self, CatalogDocument, ScopeKindEntry};
use konklav_store::registered_scopes::{self, Change, RegisteredState};
use konklav_store::roles::{self, AssignmentTarget, RoleDefinition};
use konklav_store::subjects::{self, SubjectKind};
use konklav_store::tenants::{self, ROOT};
use konklav_store::{Connection, StoreError, events, memberships};
use konklav_test_support::TestDatabase;
use serde_json::json;

fn kind(name: &str, registered: bool) -> ScopeKindEntry {
    ScopeKindEntry {
        name: name.into(),
        description: String::new(),
        registered,
    }
}

fn document() -> CatalogDocument {
    CatalogDocument {
        scope_kinds: vec![kind("document", true), kind("project", false)],
        ..CatalogDocument::default()
    }
}

fn scope(kind: &str, id: &str) -> Scope {
    Scope {
        kind: kind.into(),
        id: id.into(),
    }
}

fn record(id: &str, tenant: TenantId, projects: &[&str]) -> Change {
    Change::Record {
        kind: "document".into(),
        id: id.into(),
        tenant,
        containers: projects.iter().map(|p| scope("project", p)).collect(),
    }
}

fn remove(id: &str) -> Change {
    Change::Remove {
        kind: "document".into(),
        id: id.into(),
    }
}

async fn setup(conn: &mut Connection) -> (TenantId, TenantId) {
    catalog::replace(conn, &document()).await.unwrap();
    let a = TenantId::new_v7();
    let b = TenantId::new_v7();
    for tenant in [a, b] {
        tenants::create(conn, tenant, ROOT, &json!({}))
            .await
            .unwrap();
    }
    (a, b)
}

async fn apply(
    conn: &mut Connection,
    changes: &[Change],
) -> Result<Vec<Option<registered_scopes::RegisteredScope>>, StoreError> {
    conn.transaction::<_, StoreError, _>(async |conn| registered_scopes::apply(conn, changes).await)
        .await
}

async fn scope_events(conn: &mut Connection, after: Cursor) -> Vec<serde_json::Value> {
    events::after(conn, after, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "scope.changed")
        .map(|e| e.payload)
        .collect()
}

// r[verify authz.registered.shape]
// r[verify authz.registered.containers]
#[tokio::test(flavor = "multi_thread")]
async fn scopes_are_recorded_moved_and_removed() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (a, _) = setup(&mut conn).await;

    let recorded = apply(&mut conn, &[record("d-1", a, &["p-2", "p-1", "p-1"])])
        .await
        .unwrap();
    let recorded = recorded[0].clone().unwrap();
    assert_eq!(recorded.tenant, a);
    assert_eq!(
        recorded.containers,
        vec![scope("project", "p-1"), scope("project", "p-2")],
        "containers are kept sorted and without duplicates"
    );

    apply(&mut conn, &[record("d-1", a, &["p-3"])])
        .await
        .unwrap();
    let moved = registered_scopes::get(&mut conn, &scope("document", "d-1"))
        .await
        .unwrap();
    assert_eq!(moved.containers, vec![scope("project", "p-3")]);

    let removed = apply(&mut conn, &[remove("d-1"), remove("d-9")])
        .await
        .unwrap();
    assert_eq!(removed[0].as_ref().unwrap().state, RegisteredState::Removed);
    assert!(removed[0].as_ref().unwrap().registration().is_none());
    assert!(removed[1].is_none(), "removing an unknown scope is a no-op");

    apply(&mut conn, &[record("d-1", a, &[])]).await.unwrap();
    let again = registered_scopes::get(&mut conn, &scope("document", "d-1"))
        .await
        .unwrap();
    assert_eq!(again.state, RegisteredState::Active);
}

// r[verify authz.registered.tenant-fixed]
#[tokio::test(flavor = "multi_thread")]
async fn a_registered_scope_never_changes_tenant() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (a, b) = setup(&mut conn).await;
    apply(&mut conn, &[record("d-1", a, &[])]).await.unwrap();

    assert!(matches!(
        apply(&mut conn, &[record("d-1", b, &[])]).await,
        Err(StoreError::Conflict(_))
    ));
    apply(&mut conn, &[remove("d-1")]).await.unwrap();
    assert!(
        matches!(
            apply(&mut conn, &[record("d-1", b, &[])]).await,
            Err(StoreError::Conflict(_))
        ),
        "not even after removing it"
    );

    // The database refuses it too, for writes that skip the repository.
    let raw = diesel_async::RunQueryDsl::execute(
        diesel::sql_query(format!(
            "update registered_scope set tenant_id = '{}' where id = 'd-1'",
            b.as_uuid()
        )),
        &mut conn,
    )
    .await;
    assert!(raw.is_err());
}

// r[verify authz.registered.batch]
#[tokio::test(flavor = "multi_thread")]
async fn a_batch_is_all_or_nothing_and_names_every_problem() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (a, b) = setup(&mut conn).await;
    apply(&mut conn, &[record("d-1", a, &[])]).await.unwrap();

    let error = apply(
        &mut conn,
        &[
            record("d-2", a, &[]),
            record("d-1", b, &[]),
            record("d-3", a, &["p-1"]),
            Change::Record {
                kind: "project".into(),
                id: "p-1".into(),
                tenant: a,
                containers: vec![],
            },
            Change::Record {
                kind: "document".into(),
                id: "d-4".into(),
                tenant: a,
                containers: vec![scope("document", "d-2")],
            },
            record("d-5", TenantId::new_v7(), &[]),
            record("d-3", a, &[]),
        ],
    )
    .await
    .unwrap_err();
    let StoreError::Conflict(message) = error else {
        panic!("{error:?}");
    };
    for named in [
        "change 1 (document/d-1)",
        "change 3 (project/p-1)",
        "change 4 (document/d-4)",
        "change 5 (document/d-5)",
        "change 6 (document/d-3)",
    ] {
        assert!(message.contains(named), "{named} in {message}");
    }
    assert!(!message.contains("change 0"), "{message}");
    assert!(matches!(
        registered_scopes::get(&mut conn, &scope("document", "d-2")).await,
        Err(StoreError::NotFound)
    ));

    let too_many: Vec<Change> = (0..=registered_scopes::MAX_BATCH)
        .map(|i| record(&format!("d-{i}"), a, &[]))
        .collect();
    assert!(matches!(
        apply(&mut conn, &too_many).await,
        Err(StoreError::Conflict(_))
    ));
}

// r[verify authz.registered.events]
#[tokio::test(flavor = "multi_thread")]
async fn one_event_per_transaction_and_no_entitlement_invalidation() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (a, _) = setup(&mut conn).await;
    apply(&mut conn, &[record("d-1", a, &[])]).await.unwrap();

    let before = events::head(&mut conn).await.unwrap();
    let cursor = conn
        .transaction::<_, StoreError, _>(async |conn| {
            // Inserts and an update in one statement, then a second call.
            registered_scopes::apply(conn, &[record("d-1", a, &["p-1"]), record("d-2", a, &[])])
                .await?;
            registered_scopes::apply(conn, &[remove("d-2")]).await?;
            // Unchanged scopes aren't written again.
            registered_scopes::apply(conn, &[record("d-1", a, &["p-1"])]).await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await
        .unwrap();
    let all = events::after(&mut conn, before, 1000).await.unwrap();
    assert!(
        all.iter().all(|e| e.kind == "scope.changed"),
        "no entitlements.changed: {all:?}"
    );
    let payloads = scope_events(&mut conn, before).await;
    assert_eq!(payloads.len(), 1, "{payloads:?}");
    assert_eq!(
        cursor,
        Some(Cursor::new(all[0].cursor)),
        "the write reports the event"
    );
    let tenant = a.to_string();
    assert_eq!(
        payloads[0],
        json!({"scopes": [
            {"kind": "document", "id": "d-1", "tenant": tenant, "state": "active"},
            {"kind": "document", "id": "d-2", "tenant": tenant, "state": "active"},
            {"kind": "document", "id": "d-2", "tenant": tenant, "state": "removed"},
        ]})
    );

    let before = events::head(&mut conn).await.unwrap();
    apply(&mut conn, &[record("d-1", a, &["p-1"])])
        .await
        .unwrap();
    assert!(
        scope_events(&mut conn, before).await.is_empty(),
        "nothing changed, so no event"
    );
}

// r[verify authz.registered.catalog]
#[tokio::test(flavor = "multi_thread")]
async fn kinds_in_use_keep_their_registered_flag() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (a, _) = setup(&mut conn).await;
    apply(&mut conn, &[record("d-1", a, &["p-1"])])
        .await
        .unwrap();
    apply(&mut conn, &[remove("d-1")]).await.unwrap();

    let unregistered = CatalogDocument {
        scope_kinds: vec![kind("document", false), kind("project", false)],
        ..CatalogDocument::default()
    };
    assert!(
        matches!(
            catalog::replace(&mut conn, &unregistered).await,
            Err(StoreError::Conflict(_))
        ),
        "removed scopes keep their kind registered"
    );
    let containers_registered = CatalogDocument {
        scope_kinds: vec![kind("document", true), kind("project", true)],
        ..CatalogDocument::default()
    };
    assert!(
        matches!(
            catalog::replace(&mut conn, &containers_registered).await,
            Err(StoreError::Conflict(_))
        ),
        "a kind used by containers can't become registered"
    );
    let without_project = CatalogDocument {
        scope_kinds: vec![kind("document", true)],
        ..CatalogDocument::default()
    };
    assert!(matches!(
        catalog::replace(&mut conn, &without_project).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        catalog::load(&mut conn).await.unwrap().registered_kinds(),
        ["document".to_owned()].into()
    );
}

// r[verify authz.assignment.not-registered]
#[tokio::test(flavor = "multi_thread")]
async fn roles_cannot_be_assigned_at_registered_scopes() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (a, _) = setup(&mut conn).await;
    let subject = SubjectId::new_v7();
    subjects::create(&mut conn, subject, SubjectKind::Human)
        .await
        .unwrap();
    let membership = MembershipId::new_v7();
    memberships::create(&mut conn, membership, subject, a, &json!({}))
        .await
        .unwrap();
    let role = roles::put(&mut conn, a, "r", &RoleDefinition::default())
        .await
        .unwrap();
    assert!(matches!(
        roles::assign(
            &mut conn,
            role.id,
            AssignmentTarget::Membership(membership),
            Some(&scope("document", "d-1"))
        )
        .await,
        Err(StoreError::Conflict(_))
    ));
    roles::assign(
        &mut conn,
        role.id,
        AssignmentTarget::Membership(membership),
        Some(&scope("project", "p-1")),
    )
    .await
    .unwrap();
}
