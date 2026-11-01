use sha2::{Digest, Sha256};

/// A numeric one-time code of `digits` digits, uniformly random.
///
/// # Panics
///
/// Panics if the operating system cannot provide randomness.
#[must_use]
pub fn generate_code(digits: u32) -> String {
    let modulus = 10u64.pow(digits);
    // Rejection sampling keeps the distribution uniform.
    let limit = u64::MAX - u64::MAX % modulus;
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("system randomness");
        let value = u64::from_le_bytes(bytes);
        if value < limit {
            return format!("{:0width$}", value % modulus, width = digits as usize);
        }
    }
}

/// The stored hash of a challenge secret. The challenge id salts it, so
/// equal codes of different challenges hash differently.
// r[impl challenge.single-use]
#[must_use]
pub fn hash_challenge_secret(challenge_id: &str, secret: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(challenge_id.as_bytes());
    hasher.update([0]);
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_have_the_requested_digits() {
        for _ in 0..100 {
            let code = generate_code(6);
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn hashes_are_salted_by_challenge() {
        assert_ne!(
            hash_challenge_secret("a", "123456"),
            hash_challenge_secret("b", "123456")
        );
        assert_eq!(
            hash_challenge_secret("a", "123456"),
            hash_challenge_secret("a", "123456")
        );
    }
}
