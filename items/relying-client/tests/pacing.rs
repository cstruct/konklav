//! Pacing's timing: the work and the wait together, errors paced,
//! cancellation not.
//!
//! The checks bound durations from below, and from above only where the
//! bound is far from the expected time, so a loaded machine can't fail them.

use std::time::{Duration, Instant};

use konklav_relying_client::pacing::{Pacing, paced};

const FLOOR: Duration = Duration::from_millis(200);

fn pacing() -> Pacing {
    Pacing::new(FLOOR, Duration::ZERO)
}

// r[verify item.relying-client.pacing.concurrent]
#[tokio::test]
async fn quick_work_answers_at_the_floor() {
    let started = Instant::now();
    let answer = paced(pacing(), async { "sent" }).await;
    assert_eq!(answer, "sent");
    assert!(started.elapsed() >= FLOOR);
}

// r[verify item.relying-client.pacing.concurrent]
#[tokio::test]
async fn slow_work_adds_nothing_to_the_floor() {
    let started = Instant::now();
    paced(pacing(), tokio::time::sleep(FLOOR * 2)).await;
    let elapsed = started.elapsed();
    assert!(elapsed >= FLOOR * 2);
    // Run one after the other, it would take three floors.
    assert!(elapsed < FLOOR * 3, "{elapsed:?}");
}

// r[verify item.relying-client.pacing.errors]
#[tokio::test]
async fn errors_wait_too() {
    let started = Instant::now();
    let answer: Result<(), &str> = paced(pacing(), async { Err("unknown address") }).await;
    assert_eq!(answer, Err("unknown address"));
    assert!(started.elapsed() >= FLOOR);
}

// r[verify item.relying-client.pacing.cancellation]
#[tokio::test]
async fn cancellation_ends_the_wait() {
    let slow = Pacing::new(Duration::from_secs(30), Duration::ZERO);
    let started = Instant::now();
    let cancelled = tokio::time::timeout(Duration::from_millis(50), paced(slow, async {})).await;
    assert!(cancelled.is_err());
    assert!(started.elapsed() < Duration::from_secs(10));
}

// r[verify item.relying-client.pacing.cancellation]
#[tokio::test]
async fn panics_are_not_paced() {
    let slow = Pacing::new(Duration::from_secs(30), Duration::ZERO);
    let started = Instant::now();
    let task = tokio::spawn(paced(slow, async { panic!("work failed") }));
    assert!(task.await.unwrap_err().is_panic());
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn no_pacing_waits_not_at_all() {
    let started = Instant::now();
    paced(Pacing::NONE, async {}).await;
    assert!(started.elapsed() < Duration::from_secs(10));
}
