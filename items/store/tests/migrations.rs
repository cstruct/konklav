use conclave_test_support::TestDatabase;
use diesel_async::RunQueryDsl;

// r[verify platform.storage.forward-migrations]
#[tokio::test(flavor = "multi_thread")]
async fn a_migrated_database_has_no_pending_migrations() {
    let db = TestDatabase::new().await;
    let none = Vec::<String>::new();
    assert_eq!(
        conclave_store::pending_migrations(db.pool()).await.unwrap(),
        none
    );
    assert_eq!(
        conclave_store::run_pending_migrations(db.pool())
            .await
            .unwrap(),
        none,
        "running migrations again must be a no-op"
    );
}

// r[verify platform.storage.postgres]
#[tokio::test(flavor = "multi_thread")]
async fn an_unmigrated_database_reports_and_applies_every_migration() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    // Recreate an unmigrated state inside the isolated database.
    diesel::sql_query("drop table event")
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query("truncate __diesel_schema_migrations")
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);

    let pending = conclave_store::pending_migrations(db.pool()).await.unwrap();
    assert!(
        pending
            .iter()
            .any(|name| name.ends_with("create_event_outbox"))
    );

    let applied = conclave_store::run_pending_migrations(db.pool())
        .await
        .unwrap();
    assert_eq!(applied.len(), pending.len());
    conclave_store::ping(db.pool()).await.unwrap();
}
