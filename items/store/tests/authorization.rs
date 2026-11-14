#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;

use diesel_async::AsyncConnection;
use konklav_authz::{Effect, Group, Policy, Scope, compile};
use konklav_core::{Cursor, MembershipId, SubjectId, TenantId};
use konklav_store::catalog::{self, ActionEntry, CatalogDocument, GroupEntry, ScopeKindEntry};
use konklav_store::roles::{self, AssignmentTarget, RoleDefinition};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::tenants::{self, ROOT, TenantState};
use konklav_store::{Connection, StoreError, compile_input, events, memberships, templates};
use konklav_test_support::TestDatabase;
use serde_json::json;

fn document() -> CatalogDocument {
    CatalogDocument {
        actions: [
            "project:read",
            "document:write",
            "document:read",
            "me",
            "sys:user:list",
        ]
        .iter()
        .map(|name| ActionEntry {
            name: (*name).into(),
            description: String::new(),
            vouches: BTreeSet::new(),
        })
        .collect(),
        groups: vec![GroupEntry {
            name: "tenant:all".into(),
            description: String::new(),
            definition: Group::AllExceptPrefixes(vec!["sys:".into()]),
            vouches: BTreeSet::new(),
        }],
        scope_kinds: vec![ScopeKindEntry {
            name: "project".into(),
            description: String::new(),
            registered: false,
        }],
        ..CatalogDocument::default()
    }
}

fn allow(action: &str, scope_bound: bool) -> Policy {
    Policy {
        action: action.into(),
        effect: Effect::Allow,
        scope_bound,
    }
}

async fn setup(conn: &mut Connection) -> (SubjectId, TenantId, MembershipId) {
    catalog::replace(conn, &document()).await.unwrap();
    let subject = SubjectId::new_v7();
    subjects::create(conn, subject, SubjectKind::Human)
        .await
        .unwrap();
    let tenant = TenantId::new_v7();
    tenants::create(conn, tenant, ROOT, &json!({}))
        .await
        .unwrap();
    let membership = MembershipId::new_v7();
    memberships::create(conn, membership, subject, tenant, &json!({}))
        .await
        .unwrap();
    (subject, tenant, membership)
}

async fn kinds_since(conn: &mut Connection, after: Cursor) -> Vec<(String, serde_json::Value)> {
    events::after(conn, after, 1000)
        .await
        .unwrap()
        .into_iter()
        .map(|e| (e.kind, e.payload))
        .collect()
}

// r[verify tenant.root.bootstrap]
// r[verify tenant.tree.single-parent]
#[tokio::test(flavor = "multi_thread")]
async fn tenants_hang_off_the_root_and_are_created_idempotently() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let root = tenants::get(&mut conn, ROOT).await.unwrap();
    assert_eq!(root.parent_id, None);
    assert_eq!(tenants::parse_reference("root"), Some(ROOT));

    let id = TenantId::new_v7();
    let (tenant, created) = tenants::create(&mut conn, id, ROOT, &json!({}))
        .await
        .unwrap();
    assert!(created);
    assert_eq!(tenant.parent_id, Some(ROOT));
    assert!(
        !tenants::create(&mut conn, id, ROOT, &json!({}))
            .await
            .unwrap()
            .1
    );

    let child = TenantId::new_v7();
    tenants::create(&mut conn, child, id, &json!({}))
        .await
        .unwrap();
    assert!(matches!(
        tenants::create(&mut conn, child, ROOT, &json!({})).await,
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        tenants::create(
            &mut conn,
            TenantId::new_v7(),
            TenantId::new_v7(),
            &json!({})
        )
        .await,
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        tenants::set_state(&mut conn, ROOT, TenantState::Suspended).await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn tenant_changes_reach_the_change_feed() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let before = events::head(&mut conn).await.unwrap();
    let id = TenantId::new_v7();
    tenants::create(&mut conn, id, ROOT, &json!({}))
        .await
        .unwrap();
    tenants::set_state(&mut conn, id, TenantState::Suspended)
        .await
        .unwrap();
    let events = kinds_since(&mut conn, before).await;
    let kinds: Vec<&str> = events.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        kinds,
        ["tenant.changed", "tenant.changed", "entitlements.changed"]
    );
    assert_eq!(events[0].1["created"], true);
    assert_eq!(events[1].1["state"], "suspended");
    assert_eq!(events[2].1, json!({"all": true, "tenant": id}));
}

// r[verify membership.unique]
// r[verify membership.first-class]
// r[verify membership.state]
#[tokio::test(flavor = "multi_thread")]
async fn a_subject_has_at_most_one_active_membership_per_tenant() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (subject, tenant, membership) = setup(&mut conn).await;
    let again = memberships::create(&mut conn, membership, subject, tenant, &json!({}))
        .await
        .unwrap();
    assert!(!again.1, "same id, same subject and tenant: idempotent");
    let second = memberships::create(
        &mut conn,
        MembershipId::new_v7(),
        subject,
        tenant,
        &json!({}),
    )
    .await;
    assert!(matches!(second, Err(StoreError::Conflict(_))));

    assert!(memberships::end(&mut conn, membership).await.unwrap());
    assert!(
        memberships::find_active(&mut conn, subject, tenant)
            .await
            .unwrap()
            .is_none()
    );
    let rejoined = memberships::create(
        &mut conn,
        MembershipId::new_v7(),
        subject,
        tenant,
        &json!({}),
    )
    .await;
    assert!(rejoined.is_ok(), "a new membership after the old one ended");
}

// r[verify authz.catalog.removal]
// r[verify authz.catalog.data]
// r[verify authz.catalog.revision]
// r[verify authz.catalog.names]
#[tokio::test(flavor = "multi_thread")]
async fn catalog_entries_in_use_cannot_be_removed() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    catalog::replace(&mut conn, &document()).await.unwrap();
    assert_eq!(catalog::load(&mut conn).await.unwrap(), {
        let mut expected = document();
        expected.actions.sort_by(|a, b| a.name.cmp(&b.name));
        expected
    });
    let before = events::head(&mut conn).await.unwrap();
    catalog::replace(&mut conn, &document()).await.unwrap();
    let after = kinds_since(&mut conn, before).await;
    assert!(
        after
            .iter()
            .any(|(kind, payload)| kind == "entitlements.changed" && payload["all"] == true)
    );
    templates::put(
        &mut conn,
        "reader",
        "",
        &json!({}),
        &[allow("project:read", false)],
    )
    .await
    .unwrap();

    let mut without_read = document();
    without_read.actions.retain(|a| a.name != "project:read");
    assert!(matches!(
        catalog::replace(&mut conn, &without_read).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        catalog::load(&mut conn).await.unwrap().actions.len(),
        5,
        "nothing changed"
    );

    let mut reserved = document();
    reserved.actions.push(ActionEntry {
        name: "konklav:tenant:create".into(),
        description: String::new(),
        vouches: BTreeSet::new(),
    });
    assert!(matches!(
        catalog::replace(&mut conn, &reserved).await,
        Err(StoreError::Conflict(_))
    ));
}

/// `document()` with `action` vouching for `vouched`.
fn vouching(mut document: CatalogDocument, action: &str, vouched: &[&str]) -> CatalogDocument {
    let vouches: BTreeSet<String> = vouched.iter().map(|name| (*name).to_owned()).collect();
    if let Some(entry) = document.actions.iter_mut().find(|a| a.name == action) {
        entry.vouches = vouches;
    } else if let Some(entry) = document.groups.iter_mut().find(|g| g.name == action) {
        entry.vouches = vouches;
    } else {
        panic!("`{action}` isn't declared");
    }
    document
}

fn sorted(mut document: CatalogDocument) -> CatalogDocument {
    document.actions.sort_by(|a, b| a.name.cmp(&b.name));
    document
}

// r[verify authz.catalog.vouches]
// r[verify authz.catalog.removal]
#[tokio::test(flavor = "multi_thread")]
async fn catalog_vouches_are_stored_and_checked() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let declared = vouching(
        vouching(document(), "project:read", &["document:read", "tenant:all"]),
        "tenant:all",
        &["me"],
    );
    catalog::replace(&mut conn, &declared).await.unwrap();
    assert_eq!(catalog::load(&mut conn).await.unwrap(), sorted(declared));

    // Changing a vouch replaces it, and one declared again is kept.
    let changed = vouching(
        document(),
        "project:read",
        &["document:read", "document:write"],
    );
    catalog::replace(&mut conn, &changed).await.unwrap();
    assert_eq!(
        catalog::load(&mut conn).await.unwrap(),
        sorted(changed.clone())
    );

    // A vouched action can't be removed while a vouch names it.
    let mut without_write = changed.clone();
    without_write.actions.retain(|a| a.name != "document:write");
    assert!(matches!(
        catalog::replace(&mut conn, &without_write).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        catalog::load(&mut conn).await.unwrap(),
        sorted(changed.clone()),
        "nothing changed"
    );

    // Removing the vouch with it is fine, as is removing a vouching action.
    let without_write = vouching(without_write, "project:read", &["document:read"]);
    catalog::replace(&mut conn, &without_write).await.unwrap();
    let mut without_read = without_write.clone();
    without_read.actions.retain(|a| a.name != "project:read");
    catalog::replace(&mut conn, &without_read).await.unwrap();
    assert_eq!(
        catalog::load(&mut conn).await.unwrap(),
        sorted(without_read)
    );

    for (vouched, problem) in [
        ("project:read", "itself"),
        ("project:delete", "not declared"),
        ("konklav:tenant:create", "control-plane capability"),
    ] {
        let refused = vouching(document(), "project:read", &[vouched]);
        assert!(
            matches!(
                catalog::replace(&mut conn, &refused).await,
                Err(StoreError::Conflict(message)) if message.contains(problem)
            ),
            "a vouch for `{vouched}` is refused as {problem}"
        );
    }
}

// r[verify authz.compile.inactive]
// r[verify authz.compile.entitlements]
// r[verify authz.template.blueprint]
// r[verify authz.role.tenant-local]
// r[verify authz.assignment.membership]
// r[verify authz.compile.revision]
// r[verify authz.assignment.global]
#[tokio::test(flavor = "multi_thread")]
async fn compile_input_covers_active_global_and_tenant_assignments() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (subject, tenant, membership) = setup(&mut conn).await;

    templates::put(
        &mut conn,
        "reader",
        "",
        &json!({}),
        &[allow("project:read", false), allow("document:read", true)],
    )
    .await
    .unwrap();
    let reader = roles::put(
        &mut conn,
        tenant,
        "reader",
        &RoleDefinition {
            template: Some("reader".into()),
            ..RoleDefinition::default()
        },
    )
    .await
    .unwrap();
    let global = roles::put(
        &mut conn,
        ROOT,
        "LOG",
        &RoleDefinition {
            policies: vec![allow("me", false)],
            ..RoleDefinition::default()
        },
    )
    .await
    .unwrap();
    let p1 = Scope {
        kind: "project".into(),
        id: "p1".into(),
    };
    roles::assign(
        &mut conn,
        reader.id,
        AssignmentTarget::Membership(membership),
        Some(&p1),
    )
    .await
    .unwrap();
    roles::assign(
        &mut conn,
        global.id,
        AssignmentTarget::Subject(subject),
        None,
    )
    .await
    .unwrap();

    let input = compile_input::load(&mut conn, subject, Some(tenant))
        .await
        .unwrap();
    assert_eq!(input.revision, events::head(&mut conn).await.unwrap());
    let compiled = compile(&input.catalog, &input.assignments);
    assert_eq!(compiled.global, BTreeSet::from(["me".to_owned()]));
    assert_eq!(compiled.tenant, BTreeSet::from(["project:read".to_owned()]));
    assert_eq!(
        compiled.scoped.get(&p1),
        Some(&BTreeSet::from(["document:read".to_owned()]))
    );

    // Without a tenant only global roles count.
    let input = compile_input::load(&mut conn, subject, None).await.unwrap();
    assert_eq!(input.assignments.len(), 1);

    // An inactive tenant contributes nothing; global roles still apply.
    tenants::set_state(&mut conn, tenant, TenantState::Suspended)
        .await
        .unwrap();
    assert_eq!(
        compile_input::load(&mut conn, subject, Some(tenant))
            .await
            .unwrap()
            .assignments
            .len(),
        1
    );
    tenants::set_state(&mut conn, tenant, TenantState::Active)
        .await
        .unwrap();

    memberships::end(&mut conn, membership).await.unwrap();
    assert_eq!(
        compile_input::load(&mut conn, subject, Some(tenant))
            .await
            .unwrap()
            .assignments
            .len(),
        1
    );

    subjects::set_state(&mut conn, subject, SubjectState::Disabled)
        .await
        .unwrap();
    let disabled = compile_input::load(&mut conn, subject, Some(tenant))
        .await
        .unwrap();
    assert_eq!(
        disabled.assignments.len(),
        0,
        "disabled subjects get nothing"
    );
}

// r[verify authz.assignment.scope-kind]
#[tokio::test(flavor = "multi_thread")]
async fn assignments_stay_within_their_tenant() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (subject, tenant, membership) = setup(&mut conn).await;
    let other = TenantId::new_v7();
    tenants::create(&mut conn, other, ROOT, &json!({}))
        .await
        .unwrap();
    let foreign = roles::put(&mut conn, other, "r", &RoleDefinition::default())
        .await
        .unwrap();
    assert!(matches!(
        roles::assign(
            &mut conn,
            foreign.id,
            AssignmentTarget::Membership(membership),
            None
        )
        .await,
        Err(StoreError::Conflict(_))
    ));
    assert!(
        matches!(
            roles::assign(
                &mut conn,
                foreign.id,
                AssignmentTarget::Subject(subject),
                None
            )
            .await,
            Err(StoreError::Conflict(_)),
        ),
        "only root-owned roles are global"
    );
    let unknown_kind = Scope {
        kind: "galaxy".into(),
        id: "x".into(),
    };
    let mine = roles::put(&mut conn, tenant, "m", &RoleDefinition::default())
        .await
        .unwrap();
    assert!(
        matches!(
            roles::assign(
                &mut conn,
                mine.id,
                AssignmentTarget::Membership(membership),
                Some(&unknown_kind)
            )
            .await,
            Err(StoreError::Conflict(_))
        ),
        "scope kinds come from the catalog"
    );
}

// r[verify authz.invalidate.subject]
// r[verify authz.invalidate.definition]
// r[verify platform.idempotency.write-cursor]
#[tokio::test(flavor = "multi_thread")]
async fn writes_invalidate_entitlements_through_triggers() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (subject, tenant, membership) = setup(&mut conn).await;
    let role = roles::put(&mut conn, tenant, "r", &RoleDefinition::default())
        .await
        .unwrap();

    let before = events::head(&mut conn).await.unwrap();
    let cursor = conn
        .transaction::<_, StoreError, _>(async |conn| {
            roles::assign(
                conn,
                role.id,
                AssignmentTarget::Membership(membership),
                None,
            )
            .await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await
        .unwrap();
    let events = kinds_since(&mut conn, before).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "entitlements.changed");
    assert_eq!(
        events[0].1,
        json!({"subjects": [subject], "tenant": tenant})
    );
    assert_eq!(cursor, Some(events::head(&mut conn).await.unwrap()));

    let before = events::head(&mut conn).await.unwrap();
    roles::put(
        &mut conn,
        tenant,
        "r",
        &RoleDefinition {
            priority: 5,
            ..RoleDefinition::default()
        },
    )
    .await
    .unwrap();
    let events = kinds_since(&mut conn, before).await;
    assert!(
        events
            .iter()
            .all(|(kind, payload)| kind == "entitlements.changed" && payload["all"] == true)
    );
    assert_ne!(events.len(), 0, "a role change invalidates");

    let outside = conn
        .transaction::<_, StoreError, _>(async |conn| Ok(events::last_in_transaction(conn).await?))
        .await
        .unwrap();
    assert_eq!(
        outside, None,
        "a transaction that wrote nothing has no cursor"
    );
}

// r[verify authz.role.builtin.set]
// r[verify authz.role.reserved-key]
#[tokio::test(flavor = "multi_thread")]
async fn the_migrations_seed_exactly_the_builtin_roles() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let seeded: Vec<(String, Vec<Policy>)> = roles::list(&mut conn, ROOT)
        .await
        .unwrap()
        .into_iter()
        .filter(|role| role.builtin)
        .map(|role| (role.key, role.policies))
        .collect();
    let expected: Vec<(String, Vec<Policy>)> = roles::BUILTIN
        .iter()
        .map(|(key, capability)| {
            (
                (*key).to_owned(),
                vec![Policy {
                    action: (*capability).to_owned(),
                    effect: Effect::Allow,
                    scope_bound: false,
                }],
            )
        })
        .collect();
    assert_eq!(seeded, expected);

    let refused = roles::put(&mut conn, ROOT, "konklav.admin", &RoleDefinition::default()).await;
    assert!(matches!(refused, Err(StoreError::Reserved(_))));
    let refused = roles::delete(&mut conn, ROOT, "konklav.delivery").await;
    assert!(matches!(refused, Err(StoreError::Reserved(_))));
    assert_eq!(
        roles::get(&mut conn, ROOT, "konklav.admin")
            .await
            .unwrap()
            .policies
            .len(),
        1
    );
}

// r[verify platform.idempotency.write-cursor]
#[tokio::test(flavor = "multi_thread")]
async fn the_write_cursor_counts_events_from_savepoints() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let (_, tenant, _) = setup(&mut conn).await;
    // `roles::put` runs its own transaction: inside the caller's, that is a
    // savepoint, whose rows carry a subtransaction id.
    let cursor = conn
        .transaction::<_, StoreError, _>(async |conn| {
            roles::put(conn, tenant, "nested", &RoleDefinition::default()).await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await
        .unwrap();
    assert_eq!(cursor, Some(events::head(&mut conn).await.unwrap()));

    // A rolled-back savepoint's events don't count, and nothing leaks into
    // the next transaction.
    let before = events::head(&mut conn).await.unwrap();
    let (inner, after_rollback) = conn
        .transaction::<_, StoreError, _>(async |conn| {
            let inner = conn
                .transaction::<(), StoreError, _>(async |conn| {
                    roles::put(conn, tenant, "undone", &RoleDefinition::default()).await?;
                    Err(StoreError::Conflict("undo".into()))
                })
                .await;
            Ok((inner, events::last_in_transaction(conn).await?))
        })
        .await
        .unwrap();
    assert!(inner.is_err());
    assert_eq!(after_rollback, None);
    assert_eq!(events::head(&mut conn).await.unwrap(), before);
    let untouched = conn
        .transaction::<_, StoreError, _>(async |conn| Ok(events::last_in_transaction(conn).await?))
        .await
        .unwrap();
    assert_eq!(untouched, None);
}
