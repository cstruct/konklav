//! Response pacing for authentication endpoints.
//!
//! Hashing equalises the cost of known and unknown identifiers on login, but
//! other differences remain: a passwordless start for a known address writes
//! a challenge and a delivery event, one for an unknown address writes
//! nothing. Paced endpoints run their work and a randomised wait together
//! and respond when both are done, so their response time is the floor (plus
//! jitter) unless the work itself takes longer.

use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pacing {
    pub floor: Duration,
    pub jitter: Duration,
}

impl Pacing {
    pub const DEFAULT: Self = Self {
        floor: Duration::from_millis(1500),
        jitter: Duration::from_millis(250),
    };

    /// No wait at all, for tests.
    pub const NONE: Self = Self {
        floor: Duration::ZERO,
        jitter: Duration::ZERO,
    };

    /// A wait drawn uniformly from `floor ± jitter`.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness.
    #[must_use]
    pub fn delay(&self) -> Duration {
        let span = u64::try_from(self.jitter.as_micros() * 2).unwrap_or(u64::MAX);
        if span == 0 {
            return self.floor;
        }
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("system randomness");
        let offset = Duration::from_micros(u64::from_le_bytes(bytes) % (span + 1));
        (self.floor + offset).saturating_sub(self.jitter)
    }
}

/// Middleware pacing the routes it is applied to (see the module
/// documentation): `route_layer(from_fn_with_state(state, pace))`.
// r[impl authn.pacing]
pub async fn pace(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let wait = tokio::time::sleep(state.auth.pacing.delay());
    let (response, ()) = tokio::join!(next.run(request), wait);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_stay_within_the_jitter_of_the_floor() {
        let pacing = Pacing {
            floor: Duration::from_millis(100),
            jitter: Duration::from_millis(20),
        };
        let delays: Vec<_> = (0..1000).map(|_| pacing.delay()).collect();
        assert!(
            delays
                .iter()
                .all(|d| { (Duration::from_millis(80)..=Duration::from_millis(120)).contains(d) })
        );
        assert!(delays.iter().any(|d| *d < Duration::from_millis(95)));
        assert!(delays.iter().any(|d| *d > Duration::from_millis(105)));
    }

    #[test]
    fn no_pacing_means_no_wait() {
        assert_eq!(Pacing::NONE.delay(), Duration::ZERO);
    }
}
