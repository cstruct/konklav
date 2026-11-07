//! Fake ids: version 7 UUIDs to answer with in place of real ones.
//!
//! An endpoint that creates something, or reports what it created, can give
//! away that nothing was created: an invite to an unknown address that
//! answers with no id, or with an id that doesn't look like the others.
//! [`fake_uuid7`] makes a version 7 UUID that only the relying system's own records
//! can tell from a real one.
//!
//! A version 7 UUID carries the millisecond it was made, so the caller chooses the
//! time a fake one claims:
//!
//! - [`fake_uuid7`] claims now. Use it in place of something the request
//!   would have just created, such as the invite for an address that has no
//!   account: the real answer carries a fresh id, so the fake one must too.
//! - [`fake_uuid7_within`] claims a millisecond drawn uniformly from a past
//!   window up to now. Use it in place of something that would already
//!   exist, such as the id of an account looked up by an address that has
//!   none. A fresh id there would give the lookup away.
//!
//! ```
//! use std::time::Duration;
//!
//! use konklav_relying_client::fake_ids::{claimed_ms, fake_uuid7, fake_uuid7_within};
//!
//! let fresh = fake_uuid7();
//! assert_eq!(fresh.get_version_num(), 7);
//! let old = fake_uuid7_within(Duration::from_secs(30 * 86_400)).unwrap();
//! assert!(claimed_ms(&old) <= claimed_ms(&fake_uuid7()));
//! ```
//!
//! Everything after the timestamp is random, as RFC 9562's basic layout has
//! it. If the relying system's real ids fix some of those bits, such as
//! with a counter, the fakes differ from them in those bits; make real ids
//! the same way, or wrap this to match.
//!
//! Fake ids are worth nothing alone: the answer they're part of must be
//! paced too ([`crate::pacing`]), or how long it takes gives it away.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use uuid::Uuid;

use crate::pacing::below;

const VERSION: u128 = 0x7;
const VARIANT: u128 = 0b10;

/// A fake id's window that isn't positive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmptyWindow;

impl fmt::Display for EmptyWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a fake id's window must be positive")
    }
}

impl std::error::Error for EmptyWindow {}

/// A version 7 UUID that claims the current millisecond.
///
/// # Panics
///
/// Panics if the operating system can't provide randomness.
// r[impl item.relying-client.fake-id.time]
#[must_use]
pub fn fake_uuid7() -> Uuid {
    uuid7(now_ms())
}

/// A version 7 UUID that claims a millisecond drawn uniformly from `window` ago up
/// to now.
///
/// # Errors
///
/// [`EmptyWindow`] if `window` is zero.
///
/// # Panics
///
/// Panics if the operating system can't provide randomness.
// r[impl item.relying-client.fake-id.time]
pub fn fake_uuid7_within(window: Duration) -> Result<Uuid, EmptyWindow> {
    if window.is_zero() {
        return Err(EmptyWindow);
    }
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    let back = below(window_ms.saturating_add(1));
    Ok(uuid7(now_ms().saturating_sub(back)))
}

/// The Unix time in milliseconds a version 7 UUID claims, real or fake; `None` for
/// other versions.
///
/// ```
/// use konklav_relying_client::fake_ids::{Uuid, claimed_ms};
///
/// let id: Uuid = "01890a5d-ac96-774b-bcce-b302099a8057".parse().unwrap();
/// assert_eq!(claimed_ms(&id), Some(1_688_096_058_518));
/// ```
#[must_use]
pub fn claimed_ms(id: &Uuid) -> Option<u64> {
    if id.get_version_num() != 7 {
        return None;
    }
    u64::try_from(id.as_u128() >> 80).ok()
}

fn now_ms() -> u64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
}

// RFC 9562, section 5.7:
// unix_ts_ms (48) | ver (4) | rand_a (12) | var (2) | rand_b (62).
// r[impl item.relying-client.fake-id.layout]
fn uuid7(unix_ms: u64) -> Uuid {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("system randomness");
    let random = u128::from_le_bytes(bytes);
    let rand_a = random & ((1 << 12) - 1);
    let rand_b = (random >> 12) & ((1 << 62) - 1);
    let timestamp = u128::from(unix_ms) & ((1 << 48) - 1);
    Uuid::from_u128(timestamp << 80 | VERSION << 76 | rand_a << 64 | VARIANT << 62 | rand_b)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    // r[verify item.relying-client.fake-id.layout]
    #[test]
    fn fake_ids_are_uuid7_of_the_rfc_variant() {
        let id = fake_uuid7();
        assert_eq!(id.get_version_num(), 7);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
        // Two calls in one millisecond still differ in their random bits.
        let ids: BTreeSet<_> = (0..1000).map(|_| fake_uuid7()).collect();
        assert_eq!(ids.len(), 1000);
    }

    // r[verify item.relying-client.fake-id.layout]
    #[test]
    fn every_random_bit_varies() {
        let fixed = !(((1u128 << 48) - 1) << 80 | 0xf << 76 | 0b11 << 62);
        let varied = (0..256)
            .map(|_| fake_uuid7().as_u128() ^ fake_uuid7().as_u128())
            .fold(0, |seen, differ| seen | differ);
        assert_eq!(varied & fixed, fixed);
    }

    // r[verify item.relying-client.fake-id.time]
    #[test]
    fn fake_ids_claim_now_or_a_past_window() {
        let before = now_ms();
        let fresh = claimed_ms(&fake_uuid7()).unwrap();
        assert!((before..=now_ms()).contains(&fresh));

        let window = Duration::from_secs(3600);
        let claimed: Vec<_> = (0..1000)
            .map(|_| claimed_ms(&fake_uuid7_within(window).unwrap()).unwrap())
            .collect();
        let oldest = before - 3_600_000;
        assert!(claimed.iter().all(|ms| (oldest..=now_ms()).contains(ms)));
        // Spread over the window, not bunched at now.
        assert!(claimed.iter().any(|ms| *ms < before - 1_800_000));
        assert!(claimed.iter().any(|ms| *ms > before - 1_800_000));
    }

    // r[verify item.relying-client.fake-id.time]
    #[test]
    fn a_window_must_be_positive() {
        assert_eq!(fake_uuid7_within(Duration::ZERO), Err(EmptyWindow));
        assert!(fake_uuid7_within(Duration::from_micros(1)).is_ok());
    }

    #[test]
    fn only_uuid7_claims_a_time() {
        assert_eq!(claimed_ms(&Uuid::nil()), None);
    }
}
