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

/// Whether the cost parameters recorded in `parsed` are valid for Argon2
/// and within [`PasswordHasher`]'s limits.
fn affordable(parsed: &PasswordHash) -> bool {
    Params::try_from(parsed).is_ok_and(|params| {
        params.m_cost() <= PasswordHasher::MAX_MEMORY_KIB
            && params.t_cost() <= PasswordHasher::MAX_ITERATIONS
            && params.p_cost() <= PasswordHasher::MAX_PARALLELISM
    })
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
    /// The most memory (KiB), iterations and parallelism a stored hash may
    /// ask for: four times the default policy's memory and well above its
    /// other costs, so hashes from other systems fit, while a hash hashed
    /// elsewhere can't make every login attempt against it arbitrarily
    /// expensive.
    pub const MAX_MEMORY_KIB: u32 = 262_144;
    pub const MAX_ITERATIONS: u32 = 16;
    pub const MAX_PARALLELISM: u32 = 16;

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
    /// recorded in it. Unparsable hashes never match, and neither do hashes
    /// whose parameters cost more than the limits allow: those are refused
    /// without hashing.
    // r[impl import.credentials.cost-limit]
    #[must_use]
    pub fn verify(&self, secret: &str, stored: &str) -> PasswordCheck {
        let Ok(parsed) = PasswordHash::new(stored) else {
            return PasswordCheck::Mismatch;
        };
        if !affordable(&parsed) {
            return PasswordCheck::Mismatch;
        }
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

    /// Whether `stored` is an Argon2 PHC string, of any variant, with valid
    /// parameters within the cost limits, as [`Self::verify`] can check
    /// secrets against.
    // r[impl import.credentials.cost-limit]
    #[must_use]
    pub fn is_argon2(stored: &str) -> bool {
        PasswordHash::new(stored).is_ok_and(|parsed| {
            matches!(
                parsed.algorithm.as_str(),
                "argon2id" | "argon2i" | "argon2d"
            ) && parsed.hash.is_some()
                && parsed.salt.is_some()
                && affordable(&parsed)
        })
    }

    /// [`Self::is_argon2`], for Argon2id only.
    // r[impl credential.password.hash-input]
    #[must_use]
    pub fn is_argon2id(stored: &str) -> bool {
        stored.starts_with("$argon2id$") && Self::is_argon2(stored)
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

    /// `hash` with its parameters replaced, as an operator could plant.
    fn with_params(hash: &str, params: &str) -> String {
        let mut parts: Vec<&str> = hash.split('$').collect();
        parts[3] = params;
        parts.join("$")
    }

    // r[verify import.credentials.cost-limit]
    #[test]
    fn refuses_hashes_that_cost_too_much() {
        let hasher = cheap();
        let hash = hasher.hash("pw");
        assert!(PasswordHasher::is_argon2id(&hash));
        assert!(PasswordHasher::is_argon2id(&with_params(
            &hash,
            "m=262144,t=16,p=16"
        )));
        for params in [
            "m=262145,t=1,p=1",
            "m=4294967295,t=1,p=1",
            "m=8,t=17,p=1",
            "m=128,t=1,p=17",
        ] {
            let costly = with_params(&hash, params);
            assert!(!PasswordHasher::is_argon2id(&costly), "{params}");
            // Returns at once: hashing with these would take gigabytes.
            assert_eq!(hasher.verify("pw", &costly), PasswordCheck::Mismatch);
        }
    }

    #[test]
    fn tells_argon2_variants_apart() {
        let argon2i = "$argon2i$v=19$m=16,t=2,p=1$c29tZXNhbHQ$Iv7FuOybn2c7RtUrVZWQjQ";
        assert!(PasswordHasher::is_argon2(argon2i));
        assert!(!PasswordHasher::is_argon2id(argon2i));
        assert!(!PasswordHasher::is_argon2("plaintext"));
        assert!(!PasswordHasher::is_argon2(
            "$argon2i$v=19$m=4294967295,t=2,p=1$c29tZXNhbHQ$Iv7FuOybn2c7RtUrVZWQjQ"
        ));
    }

    // The limits leave room for the policy Konklav hashes with.
    #[test]
    fn accepts_its_default_policy() {
        let hash = "$argon2id$v=19$m=65536,t=3,p=4$MVCOUWPIMIJHbBE8MJIPLg$dPyh03xOkyCVNP5STWcNJy8ENnhtBiv84a3FtUXX7Os";
        assert!(PasswordHasher::is_argon2id(hash));
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
