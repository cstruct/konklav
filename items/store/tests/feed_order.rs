use std::time::Duration;

use diesel_async::SimpleAsyncConnection;
use konklav_core::Cursor;
use konklav_store::events;
use konklav_test_support::TestDatabase;

/// A reader that resumes from the last cursor it saw reads every event,
/// even when transactions commit in another order than they appended.
// r[verify feed.commit-order]
#[tokio::test(flavor = "multi_thread")]
async fn a_reader_never_passes_an_event_that_commits_later() {
    let db = TestDatabase::new().await;
    let mut first = db.pool().get().await.unwrap();
    let mut reader = db.pool().get().await.unwrap();

    // The first transaction appends and stays open.
    first.batch_execute("begin").await.unwrap();
    events::append(&mut first, "test.first", serde_json::json!({}))
        .await
        .unwrap();

    // A second appends and commits while the first is open. Once the fix
    // makes it wait for the first, it finishes after the first commits.
    let pool = db.pool().clone();
    let second = tokio::spawn(async move {
        let mut conn = pool.get().await.unwrap();
        conn.batch_execute("begin").await.unwrap();
        events::append(&mut conn, "test.second", serde_json::json!({}))
            .await
            .unwrap();
        conn.batch_execute("commit").await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut seen = events::after(&mut reader, Cursor::START, 100)
        .await
        .unwrap();
    let resume = seen
        .last()
        .map_or(Cursor::START, |event| Cursor::new(event.cursor));

    first.batch_execute("commit").await.unwrap();
    second.await.unwrap();
    seen.extend(events::after(&mut reader, resume, 100).await.unwrap());

    // Only this test's events; migrations seed others.
    let kinds: Vec<&str> = seen
        .iter()
        .map(|event| event.kind.as_str())
        .filter(|kind| kind.starts_with("test."))
        .collect();
    assert_eq!(
        kinds,
        ["test.first", "test.second"],
        "events read in commit order, none skipped"
    );
}
