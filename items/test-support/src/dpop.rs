//! A DPoP key for tests, standing in for a P-256 key a browser app keeps.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use konklav_token::ProofSigner;
use serde_json::Value;

/// A P-256 key that signs DPoP proofs, each with a fresh `jti`.
pub struct DpopKey {
    signer: ProofSigner,
    proofs: AtomicU64,
}

impl DpopKey {
    /// A key derived from `seed`, so tests get distinct, repeatable keys.
    ///
    /// # Panics
    ///
    /// If `seed` is 0, which isn't a valid P-256 scalar.
    #[must_use]
    pub fn new(seed: u8) -> Self {
        Self {
            signer: ProofSigner::from_secret_bytes(&[seed; 32]).expect("a valid P-256 scalar"),
            proofs: AtomicU64::new(0),
        }
    }

    /// The public key as a JWK.
    #[must_use]
    pub fn jwk(&self) -> Value {
        self.signer.jwk()
    }

    /// The key thumbprint (`jkt`).
    #[must_use]
    pub fn jkt(&self) -> String {
        self.signer.thumbprint()
    }

    /// A proof for `method` and `url`, made now, with a fresh `jti` and,
    /// given an access token, its hash.
    ///
    /// # Panics
    ///
    /// If the system clock is before 1970.
    #[must_use]
    pub fn proof(&self, method: &str, url: &str, access_token: Option<&str>) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_secs();
        let jti = format!(
            "{}-{}",
            self.jkt(),
            self.proofs.fetch_add(1, Ordering::Relaxed)
        );
        self.proof_at(
            method,
            url,
            access_token,
            i64::try_from(now).unwrap_or(i64::MAX),
            &jti,
        )
    }

    /// A proof made at `iat` (Unix seconds) with `jti`, for tests that pass
    /// their own clock.
    #[must_use]
    pub fn proof_at(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        iat: i64,
        jti: &str,
    ) -> String {
        self.signer.proof(method, url, access_token, iat, jti)
    }

    /// A proof with exactly these claims.
    #[must_use]
    pub fn sign(&self, claims: &Value) -> String {
        self.signer.sign(claims)
    }
}
