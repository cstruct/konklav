//! New identifiers for the resources the console creates.
//!
//! Konklav's creates are idempotent `PUT`s on a client-chosen id, so the
//! console mints `UUIDv7`s itself, as Konklav does.

use std::fmt::Write;

/// Formats a `UUIDv7` from a Unix time in milliseconds and ten random bytes.
///
/// ```
/// let id = konklav_console::ids::uuid_v7(0x0193_a2f1_0000, [0xff; 10]);
/// assert_eq!(id, "0193a2f1-0000-7fff-bfff-ffffffffffff");
/// ```
#[must_use]
pub fn uuid_v7(millis: u64, random: [u8; 10]) -> String {
    let mut bytes = [0u8; 16];
    bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    bytes[6..].copy_from_slice(&random);
    bytes[6] = 0x70 | (bytes[6] & 0x0f);
    bytes[8] = 0x80 | (bytes[8] & 0x3f);
    let mut id = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// A fresh `UUIDv7` from the browser's clock and random generator.
///
/// # Panics
///
/// Outside a browser.
#[must_use]
pub fn new_id() -> String {
    let mut random = [0u8; 10];
    web_sys::window()
        .and_then(|window| window.crypto().ok())
        .and_then(|crypto| crypto.get_random_values_with_u8_array(&mut random).ok())
        .expect("the browser provides crypto.getRandomValues");
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Date.now() is a positive whole number of milliseconds"
    )]
    let millis = js_sys::Date::now() as u64;
    uuid_v7(millis, random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_the_version_and_variant() {
        let id = uuid_v7(1_760_000_000_000, [0; 10]);
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "7");
        assert_eq!(&id[19..20], "8");
    }

    #[test]
    fn sorts_by_time() {
        assert!(uuid_v7(1, [0xff; 10]) < uuid_v7(2, [0; 10]));
    }
}
