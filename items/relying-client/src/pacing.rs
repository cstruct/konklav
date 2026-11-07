//! Pacing: answer no sooner than a floor plus or minus a random jitter.
//!
//! An endpoint whose answer could reveal whether a record exists, such as
//! inviting an address or starting a password reset, often does more work
//! for a known record than for an unknown one. Paced, it runs its work and a
//! wait drawn from `floor ± jitter` together, and answers when both are
//! done, so its response time is the floor (plus jitter) unless the work
//! takes longer. Konklav paces its own authentication endpoints the same
//! way.
//!
//! ```
//! use std::time::Duration;
//!
//! use konklav_relying_client::pacing::{Pacing, paced};
//!
//! # async fn maybe_send_invite(_: &str) -> Result<(), std::io::Error> { Ok(()) }
//! # async fn invite(address: &str) -> Result<(), std::io::Error> {
//! let pacing = Pacing::new(Duration::from_millis(1500), Duration::from_millis(250));
//! paced(pacing, maybe_send_invite(address)).await
//! # }
//! ```
//!
//! The wait runs whatever the work returns, so an `Err` answers no sooner
//! than an `Ok`. Cancellation is not paced: dropping the paced future drops
//! the wait with it, since whoever cancelled (a client that went away, a
//! timeout, a shutdown) isn't waiting for the answer. A panic in the work
//! isn't paced either. In tests, use [`Pacing::NONE`].
//!
//! The wait is a tokio sleep, on tokio's clock, from when the paced future
//! is first polled.

use std::future::Future;
use std::time::Duration;

/// How long a paced endpoint takes at least: `floor ± jitter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pacing {
    /// The wait's middle.
    pub floor: Duration,
    /// How far the wait may stray from the floor, either way.
    pub jitter: Duration,
}

impl Pacing {
    /// No wait at all, for tests.
    pub const NONE: Self = Self::new(Duration::ZERO, Duration::ZERO);

    /// Waits of `floor ± jitter`.
    #[must_use]
    pub const fn new(floor: Duration, jitter: Duration) -> Self {
        Self { floor, jitter }
    }

    /// A wait drawn uniformly from `floor ± jitter`, to the microsecond,
    /// and never below zero.
    ///
    /// # Panics
    ///
    /// Panics if the operating system can't provide randomness.
    // r[impl item.relying-client.pacing.delay]
    #[must_use]
    pub fn delay(&self) -> Duration {
        let span = u64::try_from(self.jitter.as_micros().saturating_mul(2)).unwrap_or(u64::MAX);
        if span == 0 {
            return self.floor;
        }
        let offset = Duration::from_micros(below(span.saturating_add(1)));
        (self.floor + offset).saturating_sub(self.jitter)
    }
}

/// Runs `work` and a wait drawn from `pacing` together, and returns the
/// work's output once both are done.
///
/// The wait is drawn when the returned future is first polled, which is
/// when the work starts.
// r[impl item.relying-client.pacing.concurrent]
// r[impl item.relying-client.pacing.errors]
// r[impl item.relying-client.pacing.cancellation]
pub async fn paced<F: Future>(pacing: Pacing, work: F) -> F::Output {
    let wait = tokio::time::sleep(pacing.delay());
    let (output, ()) = tokio::join!(work, wait);
    output
}

/// A number drawn uniformly from `0..bound`, without modulo bias.
///
/// # Panics
///
/// Panics if `bound` is zero or the operating system can't provide
/// randomness.
pub(crate) fn below(bound: u64) -> u64 {
    assert!(bound > 0, "nothing is below zero");
    // Reject the last, incomplete run of `bound` values.
    let zone = u64::MAX - (u64::MAX - bound + 1) % bound;
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("system randomness");
        let value = u64::from_le_bytes(bytes);
        if value <= zone {
            return value % bound;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    // r[verify item.relying-client.pacing.delay]
    #[test]
    fn delays_stay_within_the_jitter_of_the_floor() {
        let pacing = Pacing::new(Duration::from_millis(100), Duration::from_millis(20));
        let delays: Vec<_> = (0..1000).map(|_| pacing.delay()).collect();
        let range = Duration::from_millis(80)..=Duration::from_millis(120);
        assert!(delays.iter().all(|delay| range.contains(delay)));
        assert!(
            delays
                .iter()
                .any(|delay| *delay < Duration::from_millis(95))
        );
        assert!(
            delays
                .iter()
                .any(|delay| *delay > Duration::from_millis(105))
        );
    }

    // r[verify item.relying-client.pacing.delay]
    #[test]
    fn delays_never_go_below_zero() {
        let pacing = Pacing::new(Duration::from_millis(1), Duration::from_millis(5));
        assert!((0..1000).all(|_| pacing.delay() <= Duration::from_millis(6)));
        assert_eq!(Pacing::NONE.delay(), Duration::ZERO);
    }

    #[test]
    fn numbers_below_a_bound_cover_it() {
        let drawn: std::collections::BTreeSet<_> = (0..1000).map(|_| below(3)).collect();
        assert_eq!(drawn.into_iter().collect::<Vec<_>>(), [0, 1, 2]);
        assert_eq!(below(1), 0);
        assert!(below(u64::MAX) < u64::MAX);
    }
}
