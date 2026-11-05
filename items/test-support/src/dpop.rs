//! A DPoP key for tests, standing in for a P-256 key a browser app keeps.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};

/// A P-256 key that signs DPoP proofs, each with a fresh `jti`.
pub struct DpopKey {
    key: SigningKey,
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
            key: SigningKey::from_slice(&[seed; 32]).expect("a valid P-256 scalar"),
            proofs: AtomicU64::new(0),
        }
    }

    fn coordinates(&self) -> (Vec<u8>, Vec<u8>) {
        let point = self.key.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        (bytes[1..33].to_vec(), bytes[33..65].to_vec())
    }

    /// The public key as a JWK.
    #[must_use]
    pub fn jwk(&self) -> Value {
        let (x, y) = self.coordinates();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        })
    }

    /// The key thumbprint (`jkt`).
    #[must_use]
    pub fn jkt(&self) -> String {
        let (x, y) = self.coordinates();
        konklav_token::ec_thumbprint(&x, &y)
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
        let mut claims = json!({
            "jti": jti,
            "htm": method,
            "htu": url,
            "iat": i64::try_from(now).unwrap_or(i64::MAX),
        });
        if let Some(token) = access_token {
            claims["ath"] = json!(konklav_token::access_token_hash(token));
        }
        self.sign(&claims)
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
        let mut claims = json!({"jti": jti, "htm": method, "htu": url, "iat": iat});
        if let Some(token) = access_token {
            claims["ath"] = json!(konklav_token::access_token_hash(token));
        }
        self.sign(&claims)
    }

    /// A proof with exactly these claims.
    #[must_use]
    pub fn sign(&self, claims: &Value) -> String {
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}
