//! Tenant keys in the store: unique, set once, resolvable, and on
//! `tenant.changed`.

use diesel_async::RunQueryDsl;
use konklav_core::TenantId;
use konklav_store::tenants::{self, ROOT, Reference};
use konklav_store::{StoreError, events};
use konklav_test_support::TestDatabase;
use serde_json::json;

// r[verify tenant.key]
// r[verify tenant.key.reference]
// r[verify tenant.key.event]
#[tokio::test(flavor = "multi_thread")]
async fn keys_are_unique_set_once_and_resolve() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let start = events::head(&mut conn).await.unwrap();

    let acme = TenantId::new_v7();
    let (created, _) =
        tenants::create_with_metadata(&mut conn, acme, ROOT, &json!({}), &json!({}), Some("acme"))
            .await
            .unwrap();
    assert_eq!(created.key.as_deref(), Some("acme"));
    let other = TenantId::new_v7();
    assert!(matches!(
        tenants::create_with_metadata(&mut conn, other, ROOT, &json!({}), &json!({}), Some("acme"))
            .await,
        Err(StoreError::Conflict(_))
    ));
    tenants::create(&mut conn, other, ROOT, &json!({}))
        .await
        .unwrap();

    // Set once: the same key again changes nothing; another, or one taken,
    // is refused.
    let (keyed, set) = tenants::set_key(&mut conn, other, "acme-north")
        .await
        .unwrap();
    assert!(set);
    assert_eq!(keyed.key.as_deref(), Some("acme-north"));
    assert!(
        !tenants::set_key(&mut conn, other, "acme-north")
            .await
            .unwrap()
            .1
    );
    assert!(matches!(
        tenants::set_key(&mut conn, other, "acme-south").await,
        Err(StoreError::Conflict(_))
    ));
    let third = TenantId::new_v7();
    tenants::create(&mut conn, third, ROOT, &json!({}))
        .await
        .unwrap();
    assert!(matches!(
        tenants::set_key(&mut conn, third, "acme").await,
        Err(StoreError::Conflict(_))
    ));

    // The database refuses changing or removing a key whatever writes it.
    for statement in [
        "update tenant set key = 'renamed' where key = 'acme'",
        "update tenant set key = null where key = 'acme'",
        "update tenant set key = 'Not Valid' where key is null",
    ] {
        assert!(
            diesel::sql_query(statement)
                .execute(&mut conn)
                .await
                .is_err(),
            "{statement}"
        );
    }

    assert_eq!(
        tenants::resolve(&mut conn, &Reference::Key("acme-north".into()))
            .await
            .unwrap(),
        Some(other)
    );
    assert_eq!(
        tenants::resolve(&mut conn, &Reference::Key("nobody".into()))
            .await
            .unwrap(),
        None
    );

    let keys: Vec<serde_json::Value> = events::after(&mut conn, start, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "tenant.changed")
        .map(|event| event.payload["key"].clone())
        .collect();
    assert_eq!(
        keys,
        [json!("acme"), json!(null), json!("acme-north"), json!(null)],
        "creating carries the key, and setting one emits it"
    );
}
