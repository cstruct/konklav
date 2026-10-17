#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;

use conclave_authz::{Effect, Group, Policy, Scope, compile};
use conclave_core::{Cursor, MembershipId, SubjectId, TenantId};
use conclave_store::catalog::{self, ActionEntry, CatalogDocument, GroupEntry, ScopeKindEntry};
use conclave_store::roles::{self, AssignmentTarget, RoleDefinition};
use conclave_store::subjects::{self, SubjectKind, SubjectState};
use conclave_store::tenants::{self, ROOT, TenantState};
use conclave_store::{Connection, StoreError, compile_input, events, memberships, templates};
use conclave_test_support::TestDatabase;
use diesel_async::AsyncConnection;
use serde_json::json;

fn document() -> CatalogDocument {
    CatalogDocument {
        actions: [
            "workspace:read",
            "workspace:write",
            "patient:read",
            "me",
            "sys:user:list",
        ]
        .iter()
        .map(|name| ActionEntry {
            name: (*name).into(),
            description: String::new(),
        })
        .collect(),
        groups: vec![GroupEntry {
            name: "tenant:all".into(),
            description: String::new(),
            definition: Group::AllExceptPrefixes(vec!["sys:".into()]),
        }],
        scope_kinds: vec![ScopeKindEntry {
            name: "workspace".into(),
            description: String::new(),
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
        &[allow("workspace:read", false)],
    )
    .await
    .unwrap();

    let mut without_read = document();
    without_read.actions.retain(|a| a.name != "workspace:read");
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
        name: "conclave:tenant:create".into(),
        description: String::new(),
    });
    assert!(matches!(
        catalog::replace(&mut conn, &reserved).await,
        Err(StoreError::Conflict(_))
    ));
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
        "clinician",
        "",
        &json!({}),
        &[allow("workspace:read", false), allow("patient:read", true)],
    )
    .await
    .unwrap();
    let clinician = roles::put(
        &mut conn,
        tenant,
        "clinician",
        &RoleDefinition {
            template: Some("clinician".into()),
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
    let w1 = Scope {
        kind: "workspace".into(),
        id: "w1".into(),
    };
    roles::assign(
        &mut conn,
        clinician.id,
        AssignmentTarget::Membership(membership),
        Some(&w1),
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
    assert_eq!(
        compiled.tenant,
        BTreeSet::from(["workspace:read".to_owned()])
    );
    assert_eq!(
        compiled.scoped.get(&w1),
        Some(&BTreeSet::from(["patient:read".to_owned()]))
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
