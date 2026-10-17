use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

/// A TOTP seed (RFC 6238: HMAC-SHA1, 30-second steps, 6 digits).
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(Vec<u8>);

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret(<redacted>)")
    }
}

const STEP_SECONDS: i64 = 30;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

impl TotpSecret {
    /// A fresh 160-bit seed.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = vec![0u8; 20];
        getrandom::fill(&mut bytes).expect("system randomness");
        Self(bytes)
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The seed in unpadded base32, as authenticator apps expect.
    #[must_use]
    pub fn to_base32(&self) -> String {
        let mut out = String::new();
        let mut buffer = 0u32;
        let mut bits = 0;
        for byte in &self.0 {
            buffer = (buffer << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    /// An `otpauth://` URI for QR codes.
    #[must_use]
    pub fn uri(&self, issuer: &str, account: &str) -> String {
        format!(
            "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
            self.to_base32()
        )
    }

    /// The code for time step `step`.
    ///
    /// # Panics
    ///
    /// Never: HMAC accepts keys of any length.
    #[must_use]
    pub fn code_at_step(&self, step: i64) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(&step.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = (digest[19] & 0x0f) as usize;
        let value = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        format!("{:06}", value % 1_000_000)
    }
}

/// Checks `code` against the seed at `now` (Unix seconds), allowing one step
/// of clock skew either way. Steps at or before `last_step` are refused so a
/// code can't be replayed. Returns the matching step.
#[must_use]
pub fn verify_totp(
    secret: &TotpSecret,
    code: &str,
    now: i64,
    last_step: Option<i64>,
) -> Option<i64> {
    let current = now.div_euclid(STEP_SECONDS);
    (current - 1..=current + 1)
        .filter(|step| last_step.is_none_or(|last| *step > last))
        .find(|step| constant_time_eq(secret.code_at_step(*step).as_bytes(), code.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, SHA-1 seed "12345678901234567890".
    fn rfc_secret() -> TotpSecret {
        TotpSecret::from_bytes(b"12345678901234567890".to_vec())
    }

    #[test]
    fn matches_the_rfc_test_vectors() {
        let secret = rfc_secret();
        for (time, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(secret.code_at_step(time / 30), code, "at {time}");
        }
    }

    #[test]
    fn tolerates_one_step_of_skew_and_refuses_replays() {
        let secret = rfc_secret();
        let code = secret.code_at_step(1_234_567_890 / 30);
        assert!(verify_totp(&secret, &code, 1_234_567_890 + 30, None).is_some());
        assert!(verify_totp(&secret, &code, 1_234_567_890 + 90, None).is_none());
        let step = verify_totp(&secret, &code, 1_234_567_890, None).unwrap();
        assert!(verify_totp(&secret, &code, 1_234_567_890, Some(step)).is_none());
        assert!(verify_totp(&secret, "000000", 1_234_567_890, None).is_none() || code == "000000");
    }

    #[test]
    fn encodes_base32() {
        assert_eq!(rfc_secret().to_base32(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }
}
