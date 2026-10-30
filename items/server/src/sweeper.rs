//! The sweeper: deletes what retention allows, so no table grows without
//! bound, and erases delivery material once its challenge has expired.

use std::time::Duration;

use chrono::{DateTime, Utc};
use konklav_store::{Connection, Pool, StoreResult, events, sweep};

/// How long rows are kept, and how the sweeper runs.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// How long a session is kept after it ended.
    pub sessions: chrono::Duration,
    /// How long events stay in the outbox.
    pub events: chrono::Duration,
    pub interval: Duration,
    /// The most rows one delete removes.
    pub batch: i64,
}

/// What one sweep removed, by kind of row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub challenges: usize,
    pub login_attempts: usize,
    pub client_assertions: usize,
    pub bearer_assertions: usize,
    pub sessions: usize,
    pub delivery_material: usize,
    pub events: usize,
}

impl Swept {
    fn kinds(self) -> [(&'static str, usize); 7] {
        [
            ("challenge", self.challenges),
            ("login_attempt", self.login_attempts),
            ("client_assertion", self.client_assertions),
            ("bearer_assertion", self.bearer_assertions),
            ("session", self.sessions),
            ("delivery_material", self.delivery_material),
            ("event", self.events),
        ]
    }
}

/// The longest window in any of `limits`, in seconds.
fn longest(limits: &[&[(i64, i64)]]) -> chrono::Duration {
    chrono::Duration::seconds(
        limits
            .iter()
            .flat_map(|l| l.iter().map(|(window, _)| *window))
            .max()
            .unwrap_or(0),
    )
}

/// How long challenges are kept after they were created: send limits count
/// them over their windows.
#[must_use]
pub fn challenge_window() -> chrono::Duration {
    longest(&[&crate::flows::SEND_LIMITS])
}

/// How long login attempts are kept: rate limits count them over their
/// windows.
#[must_use]
pub fn attempt_window() -> chrono::Duration {
    longest(&[
        &crate::subject_api::RATE_LIMITS,
        &crate::subject_api::ADDRESS_LIMITS,
        &crate::flows::TOTP_LIMITS,
    ])
}

/// Repeats a batched delete until it removes fewer than a batch, adding up
/// what it removed. A macro, since async closures over the connection
/// aren't `Send`.
macro_rules! drain {
    ($batch:expr, $delete:expr) => {{
        let mut total = 0;
        loop {
            let removed: usize = $delete.await?;
            total += removed;
            if i64::try_from(removed).unwrap_or(i64::MAX) < $batch {
                break total;
            }
        }
    }};
}

/// Sweeps once as of `now`, unless another instance is sweeping. Returns
/// `None` when it didn't hold the lock.
// r[impl retention.sweep]
pub async fn sweep(
    conn: &mut Connection,
    settings: Settings,
    now: DateTime<Utc>,
) -> StoreResult<Option<Swept>> {
    if !sweep::try_lock(conn).await? {
        return Ok(None);
    }
    let swept = sweep_locked(conn, settings, now).await;
    // The lock goes with the connection if unlocking fails.
    let unlocked = sweep::unlock(conn).await;
    let swept = swept?;
    unlocked?;
    Ok(Some(swept))
}

async fn sweep_locked(
    conn: &mut Connection,
    settings: Settings,
    now: DateTime<Utc>,
) -> StoreResult<Swept> {
    let batch = settings.batch;
    let challenges_before = now - challenge_window();
    let attempts_before = now - attempt_window();
    let sessions_before = now - settings.sessions;
    Ok(Swept {
        delivery_material: drain!(batch, sweep::delivery_material(conn, now, batch)),
        challenges: drain!(
            batch,
            sweep::challenges(conn, now, challenges_before, batch)
        ),
        login_attempts: drain!(batch, sweep::login_attempts(conn, attempts_before, batch)),
        client_assertions: drain!(batch, sweep::client_assertions(conn, now, batch)),
        bearer_assertions: drain!(batch, sweep::bearer_assertions(conn, now, batch)),
        sessions: drain!(batch, sweep::sessions(conn, sessions_before, batch)),
        events: drain!(batch, async {
            Ok::<_, konklav_store::StoreError>(
                events::prune_before(conn, now - settings.events, batch).await?,
            )
        }),
    })
}

/// Sweeps every `settings.interval`, logging what went.
pub async fn sweep_forever(pool: Pool, settings: Settings) {
    loop {
        match pool.get().await {
            Ok(mut conn) => match sweep(&mut conn, settings, Utc::now()).await {
                Ok(Some(swept)) => {
                    for (kind, removed) in swept.kinds() {
                        if removed > 0 {
                            tracing::debug!(kind, removed, "swept");
                        }
                    }
                }
                Ok(None) => tracing::debug!("another instance is sweeping"),
                Err(error) => tracing::warn!(%error, "sweeping failed"),
            },
            Err(error) => tracing::warn!(%error, "sweeping failed"),
        }
        tokio::time::sleep(settings.interval).await;
    }
}
