use std::sync::OnceLock;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};

/// The outcome of checking a password (or secret key) against a stored hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordCheck {
    /// It matches. When `needs_rehash` is set, the stored hash uses other
    /// parameters than the current policy and should be replaced.
    Match {
        needs_rehash: bool,
    },
    Mismatch,
}

/// Hashes and verifies secrets with Argon2id.
///
/// The default policy (t=3, m=64 MiB, p=4, 32-byte output, 16-byte salt)
/// matches the hashes produced by existing relying systems, so imported
/// hashes verify without needing a rehash.
// r[impl credential.password.hashing]
#[derive(Clone, Debug)]
pub struct PasswordHasher {
    params: Params,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new(65_536, 3, 4).expect("default Argon2 parameters are valid")
    }
}

impl PasswordHasher {
    /// A hasher with the given memory (KiB), iterations and parallelism.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, argon2::Error> {
        Ok(Self {
            params: Params::new(memory_kib, iterations, parallelism, Some(32))?,
        })
    }

    fn argon2(&self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }

    /// Hashes `secret` into a PHC string with a fresh random salt.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness.
    #[must_use]
    pub fn hash(&self, secret: &str) -> String {
        self.argon2()
            .hash_password(secret.as_bytes())
            .expect("hashing with valid parameters and system randomness")
            .to_string()
    }

    /// Checks `secret` against a stored PHC string, using the parameters
    /// recorded in it. Unparsable hashes never match.
    #[must_use]
    pub fn verify(&self, secret: &str, stored: &str) -> PasswordCheck {
        let Ok(parsed) = PasswordHash::new(stored) else {
            return PasswordCheck::Mismatch;
        };
        if self
            .argon2()
            .verify_password(secret.as_bytes(), &parsed)
            .is_err()
        {
            return PasswordCheck::Mismatch;
        }
        let current = parsed.algorithm.as_str() == "argon2id"
            && parsed.version == Some(Version::V0x13.into())
            && Params::try_from(&parsed).is_ok_and(|params| params == self.params);
        PasswordCheck::Match {
            needs_rehash: !current,
        }
    }

    /// Spends the same effort as a real verification without any stored
    /// hash, so that failures for unknown identifiers take as long as
    /// failures for wrong secrets.
    // r[impl authn.login.timing]
    pub fn verify_dummy(&self, secret: &str) {
        static DUMMY: OnceLock<String> = OnceLock::new();
        let dummy = DUMMY.get_or_init(|| self.hash("konklav-timing-equalizer"));
        let _ = self.verify(secret, dummy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A cheap policy keeps the tests fast; the default is exercised once.
    fn cheap() -> PasswordHasher {
        PasswordHasher::new(8, 1, 1).unwrap()
    }

    #[test]
    fn verifies_its_own_hashes() {
        let hasher = cheap();
        let hash = hasher.hash("correct horse");
        assert!(hash.starts_with("$argon2id$v=19$"));
        assert_eq!(
            hasher.verify("correct horse", &hash),
            PasswordCheck::Match {
                needs_rehash: false
            }
        );
        assert_eq!(hasher.verify("wrong", &hash), PasswordCheck::Mismatch);
    }

    #[test]
    fn salts_every_hash() {
        let hasher = cheap();
        assert_ne!(hasher.hash("same"), hasher.hash("same"));
    }

    #[test]
    fn asks_for_a_rehash_when_parameters_changed() {
        let old = PasswordHasher::new(16, 1, 1).unwrap().hash("pw");
        assert_eq!(
            cheap().verify("pw", &old),
            PasswordCheck::Match { needs_rehash: true }
        );
    }

    #[test]
    fn never_matches_garbage() {
        assert_eq!(cheap().verify("pw", "not a hash"), PasswordCheck::Mismatch);
        assert_eq!(cheap().verify("pw", ""), PasswordCheck::Mismatch);
    }

    // r[verify credential.password.hashing]
    #[test]
    fn verifies_hashes_from_argon2_cffi_without_rehashing() {
        // Produced by Python's argon2-cffi with
        // PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
        //                hash_len=32, salt_len=16, type=Type.ID).hash("hunter2")
        let imported = "$argon2id$v=19$m=65536,t=3,p=4$MVCOUWPIMIJHbBE8MJIPLg$dPyh03xOkyCVNP5STWcNJy8ENnhtBiv84a3FtUXX7Os";
        let hasher = PasswordHasher::default();
        assert_eq!(
            hasher.verify("hunter2", imported),
            PasswordCheck::Match {
                needs_rehash: false
            }
        );
        assert_eq!(hasher.verify("hunter3", imported), PasswordCheck::Mismatch);
    }
}
